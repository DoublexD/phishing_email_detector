"""
Model Training
Trening modeli uczenia maszynowego do wykrywania spoofingu
"""
# pyright: reportAttributeAccessIssue=false, reportCallIssue=false
# pyright: reportArgumentType=false, reportAssignmentType=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportReturnType=false, reportOptionalSubscript=false

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import (
    train_test_split, cross_val_score, GridSearchCV,
    StratifiedKFold, RandomizedSearchCV
)
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_curve, f1_score, roc_auc_score
)
from sklearn.calibration import CalibratedClassifierCV
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Klasa do trenowania modeli ML"""
    
    def __init__(self, 
                 random_state: int = 42,
                 models_dir: str = "models"):
        """
        Inicjalizacja trainera
        """
        self.random_state = random_state
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.random_forest = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
    
    def prepare_data(self, 
                    X: pd.DataFrame, 
                    y: pd.Series,
                    test_size: float = 0.2,
                    balance_data: bool = True) -> Tuple:
        """
        Przygotowuje dane do treningu: dzieli je na train/test, skaluje i opcjonalnie balansuje train przez SMOTE.
        """
        logger.info(f"Przygotowanie danych: {X.shape[0]} próbek, {X.shape[1]} cech")
        
        self.feature_names = X.columns.tolist()
        
        n_classes = y.nunique()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.random_state,
            stratify=y if n_classes > 1 else None
        )
        
        if n_classes < 2:
            logger.warning(f"Tylko {n_classes} klasa w danych — wyniki mogą być niewiarygodne")
        
        logger.info(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")
        logger.info(f"Rozkład klas (train): {y_train.value_counts().to_dict()}")

        self._X_calib_scaled: Optional[pd.DataFrame] = None
        self._y_calib: Optional[pd.Series] = None

        X_fit: pd.DataFrame = X_train
        y_fit: pd.Series = y_train
        X_calib: Optional[pd.DataFrame] = None
        y_calib: Optional[pd.Series] = None

        min_per_class = y_train.value_counts().min() if n_classes > 1 else len(y_train)
        use_calib = len(X_train) >= 50 and min_per_class >= 3
        if use_calib:
            try:
                X_fit, X_calib, y_fit, y_calib = train_test_split(
                    X_train, y_train, test_size=0.2, random_state=self.random_state,
                    stratify=y_train if n_classes > 1 else None,
                )
            except ValueError:
                use_calib = False
                X_fit, y_fit = X_train, y_train
                X_calib, y_calib = None, None

        self._X_train_original = X_fit.copy()
        self._y_train_original = y_fit.copy()
        
        self.scaler = StandardScaler()
        X_fit_scaled = pd.DataFrame(
            self.scaler.fit_transform(X_fit), columns=X_train.columns
        )
        X_test_scaled = pd.DataFrame(
            self.scaler.transform(X_test), columns=X_train.columns
        )
        if X_calib is not None:
            self._X_calib_scaled = pd.DataFrame(
                self.scaler.transform(X_calib), columns=X_train.columns
            )
            self._y_calib = y_calib
            logger.info(
                f"Kalibracja progów: {len(self._y_calib)} próbek (nieużywane w SMOTE/treningu RF)"
            )

        self._X_train_scaled_presmote = X_fit_scaled.copy()
        self._y_train_presmote = y_fit.copy()
        
        X_train_scaled = X_fit_scaled
        y_train = y_fit
        
        if balance_data and len(y_train.unique()) > 1:
            try:
                smote = SMOTE(random_state=self.random_state)
                X_train_scaled, y_train = smote.fit_resample(X_train_scaled, y_train)
                logger.info(f"SMOTE: {X_train_scaled.shape[0]} próbek (train)")
                logger.info(f"Rozkład po SMOTE: {pd.Series(y_train).value_counts().to_dict()}")
            except Exception as e:
                logger.warning(f"SMOTE nie powiodło się: {e}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_random_forest(self,
                           X_train: pd.DataFrame,
                           y_train: pd.Series,
                           hyperparameter_tuning: bool = False) -> RandomForestClassifier:
        """
        Trenuje Random Forest. Przy tuningu dobiera parametry przez RandomizedSearchCV,
        stosując SMOTE wewnątrz foldów CV, żeby uniknąć wycieku danych.
        """
        logger.info("Trening modelu Random Forest...")
        
        if hyperparameter_tuning:
            param_distributions = {
                'rf__n_estimators': [100, 200, 300, 500],
                'rf__max_depth': [10, 15, 20, 30, None],
                'rf__min_samples_split': [2, 5, 10, 15],
                'rf__min_samples_leaf': [1, 2, 4, 8],
                'rf__max_features': ['sqrt', 'log2', 0.3, 0.5],
                'rf__class_weight': ['balanced', 'balanced_subsample'],
                'rf__criterion': ['gini', 'entropy'],
            }
            
            imb_pipeline = ImbPipeline([
                ('smote', SMOTE(random_state=self.random_state)),
                ('rf', RandomForestClassifier(random_state=self.random_state, n_jobs=-1))
            ])
            
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_state)
            
            X_cv = self._X_train_scaled_presmote
            y_cv = self._y_train_presmote
            
            search = RandomizedSearchCV(
                imb_pipeline, param_distributions,
                n_iter=60, cv=cv, scoring='f1',
                n_jobs=-1, verbose=1,
                random_state=self.random_state,
                refit=False
            )
            search.fit(X_cv, y_cv)
            
            best_params = {k.replace('rf__', ''): v for k, v in search.best_params_.items()
                           if k.startswith('rf__')}
            logger.info(f"Najlepsze parametry (CV z SMOTE wewnątrz foldów): {best_params}")
            logger.info(f"Najlepszy F1 (CV): {search.best_score_:.4f}")
            
            self.random_forest = RandomForestClassifier(
                **best_params,
                random_state=self.random_state,
                n_jobs=-1,
                oob_score=True
            )
            self.random_forest.fit(X_train, y_train)
        else:
            self.random_forest = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                class_weight='balanced',
                random_state=self.random_state,
                n_jobs=-1,
                oob_score=True
            )
            self.random_forest.fit(X_train, y_train)
        
        if hasattr(self.random_forest, 'oob_score_') and self.random_forest.oob_score_:
            logger.info(f"OOB Score: {self.random_forest.oob_score_:.4f}")

        if hasattr(self, '_X_train_scaled_presmote'):
            try:
                imb_cv_pipeline = ImbPipeline([
                    ('smote', SMOTE(random_state=self.random_state)),
                    ('rf', self.random_forest)
                ])
                cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_state)
                cv_scores = cross_val_score(
                    imb_cv_pipeline, self._X_train_scaled_presmote,
                    self._y_train_presmote, cv=cv, scoring='f1', n_jobs=-1
                )
                logger.info(f"Cross-validation F1 (SMOTE w foldach): "
                             f"{cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
            except Exception as e:
                logger.warning(f"CV z imblearn pipeline nie powiodło się: {e}")
        
        return self.random_forest
    
    def train_isolation_forest(self,
                               X_train: pd.DataFrame,
                               contamination: Optional[float] = None) -> IsolationForest:
        """
        Trenuje Isolation Forest na danych bez SMOTE, model anomalii powinien uczyć się
        oryginalnego rozkładu danych. Contamination jest liczone automatycznie.
        """
        logger.info("Trening modelu Isolation Forest...")
        
        if hasattr(self, '_X_train_scaled_presmote'):
            X_if = self._X_train_scaled_presmote
            y_if = self._y_train_presmote
        else:
            X_if = X_train
            y_if = None
        
        if contamination is None and y_if is not None:
            contamination = float(y_if.sum()) / len(y_if)
            logger.info(f"Auto contamination: {contamination:.4f} "
                         f"(z proporcji phishingu w danych)")
        elif contamination is None:
            contamination = 0.1
        
        best_f1 = -1
        best_if = None
        best_params = {}
        
        param_candidates = [
            {'n_estimators': 200, 'max_samples': 256, 'max_features': 1.0},
            {'n_estimators': 300, 'max_samples': 512, 'max_features': 1.0},
            {'n_estimators': 200, 'max_samples': 'auto', 'max_features': 0.8},
            {'n_estimators': 300, 'max_samples': 'auto', 'max_features': 0.5},
            {'n_estimators': 500, 'max_samples': 256, 'max_features': 0.8},
        ]
        
        for params in param_candidates:
            iforest = IsolationForest(
                contamination=contamination,
                random_state=self.random_state,
                n_jobs=-1,
                **params
            )
            iforest.fit(X_if)
            
            if y_if is not None:
                preds = iforest.predict(X_if)
                preds_binary = np.where(preds == -1, 1, 0)
                f1 = f1_score(y_if, preds_binary, zero_division=0)
                
                if f1 > best_f1:
                    best_f1 = f1
                    best_if = iforest
                    best_params = params
            else:
                best_if = iforest
                break
        
        self.isolation_forest = best_if
        
        if best_params:
            logger.info(f"IF najlepsze parametry: {best_params}, F1 (train): {best_f1:.4f}")
        
        train_pred = self.isolation_forest.predict(X_if)
        anomalies = np.sum(train_pred == -1)
        logger.info(f"IF wykryto {anomalies} anomalii "
                     f"({anomalies/len(X_if)*100:.2f}%)")
        
        return self.isolation_forest
    
    def _find_optimal_threshold(self,
                                X_val: pd.DataFrame,
                                y_val: pd.Series) -> float:
        """
        Znajduje optymalny próg decyzyjny dla RF metodą precision-recall curve.
        Domyślny próg 0.5 nie jest optymalny przy niezbalansowanych danych.
        """
        if not self.random_forest:
            return 0.5
        
        y_proba = self.random_forest.predict_proba(X_val)[:, 1]
        precisions, recalls, thresholds = precision_recall_curve(y_val, y_proba)
        
        f1_scores = np.where(
            (precisions[:-1] + recalls[:-1]) > 0,
            2 * precisions[:-1] * recalls[:-1] / (precisions[:-1] + recalls[:-1]),
            0
        )
        
        best_idx = np.argmax(f1_scores)
        best_threshold = float(thresholds[best_idx])
        best_f1 = float(f1_scores[best_idx])
        
        logger.info(f"Optymalny próg: {best_threshold:.4f} (F1={best_f1:.4f})")
        logger.info(f"  vs domyślny 0.5: precision={precisions[0]:.4f}, recall={recalls[0]:.4f}")
        
        return best_threshold
    
    def evaluate(self,
                X_test: pd.DataFrame,
                y_test: pd.Series) -> Dict[str, Any]:
        """
        Ewaluuje wytrenowane modele z optymalnym progiem decyzyjnym.
        """
        results = {}

        if self.random_forest:
            logger.info("Ewaluacja Random Forest...")
            y_pred_proba_rf = self.random_forest.predict_proba(X_test)[:, 1]

            if getattr(self, '_X_calib_scaled', None) is not None and len(self._X_calib_scaled) > 0:
                self.optimal_threshold = self._find_optimal_threshold(
                    self._X_calib_scaled, self._y_calib
                )
            else:
                logger.warning(
                    "Brak zbioru kalibracji — próg RF=0.5 (rozważ więcej danych treningowych)"
                )
                self.optimal_threshold = 0.5
            
            y_pred_rf_default = (y_pred_proba_rf >= 0.5).astype(int)
            y_pred_rf_optimal = (y_pred_proba_rf >= self.optimal_threshold).astype(int)
            
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba_rf)
            except ValueError:
                roc_auc = 0.0
            
            results['random_forest'] = {
                'classification_report': classification_report(y_test, y_pred_rf_optimal, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred_rf_optimal).tolist(),
                'predictions': y_pred_rf_optimal.tolist(),
                'probabilities': y_pred_proba_rf.tolist(),
                'optimal_threshold': self.optimal_threshold,
                'roc_auc': roc_auc,
                'default_threshold_report': classification_report(y_test, y_pred_rf_default, output_dict=True),
            }
            
            feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.random_forest.feature_importances_
            }).sort_values('importance', ascending=False)
            
            results['random_forest']['feature_importance'] = feature_importance.head(25).to_dict('records')
            
            logger.info(f"\nRandom Forest (próg={self.optimal_threshold:.3f}):")
            logger.info(classification_report(y_test, y_pred_rf_optimal))
            logger.info(f"ROC AUC: {roc_auc:.4f}")

        if self.isolation_forest:
            logger.info("Ewaluacja Isolation Forest...")
            y_pred_if = self.isolation_forest.predict(X_test)
            y_pred_if_binary = np.where(y_pred_if == -1, 1, 0)
            if_scores = self.isolation_forest.score_samples(X_test)
            
            results['isolation_forest'] = {
                'classification_report': classification_report(y_test, y_pred_if_binary, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred_if_binary).tolist(),
                'predictions': y_pred_if_binary.tolist(),
                'anomaly_scores': if_scores.tolist()
            }
            
            logger.info("\nIsolation Forest:")
            logger.info(classification_report(y_test, y_pred_if_binary))

        if self.random_forest and self.isolation_forest:
            ensemble_result = self._evaluate_weighted_ensemble(X_test, y_test)
            results['weighted_ensemble'] = ensemble_result
        
        return results
    
    def _evaluate_weighted_ensemble(self,
                                     X_test: pd.DataFrame,
                                     y_test: pd.Series) -> Dict[str, Any]:
        """
        Ewaluacja ważonego ensemble RF + IF.
        RF dostaje większą wagę (lepsze wyniki), IF służy jako dodatkowy sygnał anomalii.
        """
        rf_proba = self.random_forest.predict_proba(X_test)[:, 1]
        
        if_scores_raw = self.isolation_forest.score_samples(X_test)
        if_proba = 1.0 - (if_scores_raw - if_scores_raw.min()) / \
                   (if_scores_raw.max() - if_scores_raw.min() + 1e-10)
        
        rf_weight, if_weight = 0.75, 0.25
        ensemble_proba = rf_weight * rf_proba + if_weight * if_proba

        best_f1 = 0.0
        best_thresh = 0.5
        Xc = getattr(self, '_X_calib_scaled', None)
        yc = getattr(self, '_y_calib', None)
        if Xc is not None and yc is not None and len(Xc) > 0:
            rf_c = self.random_forest.predict_proba(Xc)[:, 1]
            raw_c = self.isolation_forest.score_samples(Xc)
            if_c = 1.0 - (raw_c - raw_c.min()) / (raw_c.max() - raw_c.min() + 1e-10)
            ens_c = rf_weight * rf_c + if_weight * if_c
            for thresh in np.arange(0.3, 0.8, 0.02):
                preds = (ens_c >= thresh).astype(int)
                f1 = f1_score(yc, preds, zero_division=0)
                if f1 > best_f1:
                    best_f1 = f1
                    best_thresh = thresh
            logger.info(f"Ensemble: próg z kalibracji={best_thresh:.3f} (F1_calib={best_f1:.4f})")
        else:
            for thresh in np.arange(0.3, 0.8, 0.02):
                preds = (ensemble_proba >= thresh).astype(int)
                f1 = f1_score(y_test, preds, zero_division=0)
                if f1 > best_f1:
                    best_f1 = f1
                    best_thresh = thresh
            logger.warning(
                "Ensemble: brak kalibracji — próg dopasowany do zbioru testowego (mniej wiarygodny OOT)"
            )
        
        y_pred_ensemble = (ensemble_proba >= best_thresh).astype(int)
        
        logger.info(f"\nWeighted Ensemble (RF={rf_weight}, IF={if_weight}, próg={best_thresh:.3f}):")
        logger.info(classification_report(y_test, y_pred_ensemble))
        
        self.ensemble_weights = {'rf': rf_weight, 'if': if_weight}
        self.ensemble_threshold = best_thresh
        
        return {
            'classification_report': classification_report(y_test, y_pred_ensemble, output_dict=True),
            'confusion_matrix': confusion_matrix(y_test, y_pred_ensemble).tolist(),
            'weights': {'random_forest': rf_weight, 'isolation_forest': if_weight},
            'threshold': best_thresh,
            'predictions': y_pred_ensemble.tolist(),
            'probabilities': ensemble_proba.tolist(),
        }
    
    def save_models(self, prefix: str = ""):
        """
        Zapisuje wytrenowane modele, próg decyzyjny i konfigurację ensemble.
        """
        if prefix:
            prefix = f"{prefix}_"

        if self.random_forest:
            rf_path = self.models_dir / f"{prefix}random_forest_classifier.joblib"
            joblib.dump(self.random_forest, rf_path)
            logger.info(f"Zapisano Random Forest: {rf_path}")

        if self.isolation_forest:
            if_path = self.models_dir / f"{prefix}isolation_forest_anomaly.joblib"
            joblib.dump(self.isolation_forest, if_path)
            logger.info(f"Zapisano Isolation Forest: {if_path}")

        if self.scaler:
            scaler_path = self.models_dir / f"{prefix}scaler.joblib"
            joblib.dump(self.scaler, scaler_path)
            logger.info(f"Zapisano Scaler: {scaler_path}")

        if self.feature_names:
            features_path = self.models_dir / f"{prefix}feature_names.joblib"
            joblib.dump(self.feature_names, features_path)
            logger.info(f"Zapisano nazwy cech: {features_path}")

        model_config = {
            'optimal_threshold': getattr(self, 'optimal_threshold', 0.5),
            'ensemble_weights': getattr(self, 'ensemble_weights', {'rf': 0.75, 'if': 0.25}),
            'ensemble_threshold': getattr(self, 'ensemble_threshold', 0.5),
        }
        config_path = self.models_dir / f"{prefix}model_config.joblib"
        joblib.dump(model_config, config_path)
        logger.info(f"Zapisano konfigurację modeli: {config_path}")
    
    def full_training_pipeline(self,
                              X: pd.DataFrame,
                              y: pd.Series,
                              test_size: float = 0.2,
                              hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Uruchamia pełny trening: przygotowuje dane, trenuje modele, ocenia je,
        zapisuje modele oraz wyniki ewaluacji.
        """
        X_train, X_test, y_train, y_test = self.prepare_data(X, y, test_size)

        self.train_random_forest(X_train, y_train, hyperparameter_tuning)
        self.train_isolation_forest(X_train)

        results = self.evaluate(X_test, y_test)

        self.save_models()

        self._save_evaluation_results(results, X, y)
        
        return results
    
    def _save_evaluation_results(self, results: Dict[str, Any],
                                  X: pd.DataFrame, y: pd.Series):
        """Zapisuje wyniki ewaluacji do pliku JSON"""
        import json
        
        eval_data = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'dataset': {
                'total_samples': len(y),
                'positive_samples': int(y.sum()),
                'negative_samples': int((y == 0).sum()),
                'feature_count': X.shape[1],
                'feature_names': X.columns.tolist()
            },
            'training_config': {
                'optimal_threshold': getattr(self, 'optimal_threshold', 0.5),
                'ensemble_weights': getattr(self, 'ensemble_weights', None),
                'ensemble_threshold': getattr(self, 'ensemble_threshold', None),
            },
            'models': {}
        }
        
        for model_name, model_results in results.items():
            report = model_results.get('classification_report', {})
            model_data = {
                'precision': report.get('1', report.get('1.0', {})).get('precision', 0),
                'recall': report.get('1', report.get('1.0', {})).get('recall', 0),
                'f1_score': report.get('1', report.get('1.0', {})).get('f1-score', 0),
                'accuracy': report.get('accuracy', 0),
                'confusion_matrix': model_results.get('confusion_matrix', []),
                'classification_report': report,
            }
            if 'roc_auc' in model_results:
                model_data['roc_auc'] = model_results['roc_auc']
            if 'optimal_threshold' in model_results:
                model_data['optimal_threshold'] = model_results['optimal_threshold']
            if 'weights' in model_results:
                model_data['weights'] = model_results['weights']
            if 'feature_importance' in model_results:
                model_data['feature_importance'] = model_results['feature_importance']
            
            eval_data['models'][model_name] = model_data
        
        eval_path = self.models_dir / "evaluation_results.json"
        with open(eval_path, 'w', encoding='utf-8') as f:
            json.dump(eval_data, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"Zapisano wyniki ewaluacji: {eval_path}")


def main():
    """Główna funkcja do treningu modeli"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Trening modeli wykrywania spoofingu')
    parser.add_argument('--data', type=str, required=True, help='Ścieżka do pliku CSV z danymi')
    parser.add_argument('--target', type=str, default='is_phishing', help='Nazwa kolumny z etykietami')
    parser.add_argument('--test-size', type=float, default=0.2, help='Proporcja zbioru testowego')
    parser.add_argument('--tune', action='store_true', help='Przeprowadź tuning hiperparametrów')
    parser.add_argument('--models-dir', type=str, default='models', help='Katalog do zapisywania modeli')
    
    args = parser.parse_args()

    logger.info(f"Ładowanie danych z: {args.data}")
    df = pd.read_csv(args.data)

    y = df[args.target]
    X = df.drop(columns=[args.target])

    trainer = ModelTrainer(models_dir=args.models_dir)
    results = trainer.full_training_pipeline(X, y, args.test_size, args.tune)
    
    logger.info("Trening zakończony!")
    logger.info(f"Wyniki zapisano w: {args.models_dir}")


if __name__ == '__main__':
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    from utils.helpers import setup_logging
    setup_logging()
    main()

