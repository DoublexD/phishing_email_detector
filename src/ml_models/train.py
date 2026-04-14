"""
Model Training
Trening modeli uczenia maszynowego do wykrywania spoofingu
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
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
        
        Args:
            random_state: Ziarno losowości dla powtarzalności
            models_dir: Katalog do zapisywania modeli
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
        Przygotowuje dane do treningu
        
        Args:
            X: Cechy
            y: Etykiety (0 = bezpieczne, 1 = spoofing/phishing)
            test_size: Proporcja zbioru testowego
            balance_data: Czy zbalansować dane używając SMOTE
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info(f"Przygotowanie danych: {X.shape[0]} próbek, {X.shape[1]} cech")
        
        # Zapisz nazwy cech
        self.feature_names = X.columns.tolist()
        
        # Podział na train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.random_state, stratify=y
        )
        
        logger.info(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")
        logger.info(f"Rozkład klas (train): {y_train.value_counts().to_dict()}")
        
        # Balansowanie danych (SMOTE)
        if balance_data and len(y_train.unique()) > 1:
            try:
                smote = SMOTE(random_state=self.random_state)
                X_train, y_train = smote.fit_resample(X_train, y_train)
                logger.info(f"Zbalansowano dane: {X_train.shape[0]} próbek")
                logger.info(f"Nowy rozkład klas: {pd.Series(y_train).value_counts().to_dict()}")
            except Exception as e:
                logger.warning(f"Nie udało się zbalansować danych: {e}")
        
        # Skalowanie cech
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Konwertuj z powrotem na DataFrame (zachowaj nazwy kolumn)
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_random_forest(self,
                           X_train: pd.DataFrame,
                           y_train: pd.Series,
                           hyperparameter_tuning: bool = False) -> RandomForestClassifier:
        """
        Trenuje model Random Forest
        
        Args:
            X_train: Dane treningowe
            y_train: Etykiety treningowe
            hyperparameter_tuning: Czy przeprowadzić tuning hiperparametrów
            
        Returns:
            Wytrenowany model
        """
        logger.info("Trening modelu Random Forest...")
        
        if hyperparameter_tuning:
            # Grid Search dla najlepszych parametrów
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [10, 20, 30, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'class_weight': ['balanced', 'balanced_subsample']
            }
            
            rf = RandomForestClassifier(random_state=self.random_state)
            grid_search = GridSearchCV(
                rf, param_grid, cv=5, scoring='f1', n_jobs=-1, verbose=1
            )
            grid_search.fit(X_train, y_train)
            
            self.random_forest = grid_search.best_estimator_
            logger.info(f"Najlepsze parametry: {grid_search.best_params_}")
            logger.info(f"Najlepszy wynik F1: {grid_search.best_score_:.4f}")
        else:
            # Domyślne parametry
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                class_weight='balanced',
                random_state=self.random_state,
                n_jobs=-1
            )
            self.random_forest.fit(X_train, y_train)
        
        # Cross-validation score
        cv_scores = cross_val_score(
            self.random_forest, X_train, y_train, cv=5, scoring='f1'
        )
        logger.info(f"Cross-validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        return self.random_forest
    
    def train_isolation_forest(self,
                               X_train: pd.DataFrame,
                               contamination: float = 0.1) -> IsolationForest:
        """
        Trenuje model Isolation Forest (wykrywanie anomalii)
        
        Args:
            X_train: Dane treningowe
            contamination: Oczekiwana proporcja anomalii
            
        Returns:
            Wytrenowany model
        """
        logger.info("Trening modelu Isolation Forest...")
        
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            max_samples=256,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.isolation_forest.fit(X_train)
        
        # Predykcje na zbiorze treningowym (dla diagnostyki)
        train_pred = self.isolation_forest.predict(X_train)
        anomalies = np.sum(train_pred == -1)
        logger.info(f"Wykryto {anomalies} anomalii w zbiorze treningowym ({anomalies/len(X_train)*100:.2f}%)")
        
        return self.isolation_forest
    
    def evaluate(self,
                X_test: pd.DataFrame,
                y_test: pd.Series) -> Dict[str, Any]:
        """
        Ewaluuje wytrenowane modele
        
        Args:
            X_test: Dane testowe
            y_test: Etykiety testowe
            
        Returns:
            Słownik z metrykami
        """
        results = {}
        
        # Random Forest
        if self.random_forest:
            logger.info("Ewaluacja Random Forest...")
            y_pred_rf = self.random_forest.predict(X_test)
            y_pred_proba_rf = self.random_forest.predict_proba(X_test)[:, 1]
            
            results['random_forest'] = {
                'classification_report': classification_report(y_test, y_pred_rf, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred_rf).tolist(),
                'predictions': y_pred_rf.tolist(),
                'probabilities': y_pred_proba_rf.tolist()
            }
            
            # Feature importance
            feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.random_forest.feature_importances_
            }).sort_values('importance', ascending=False)
            
            results['random_forest']['feature_importance'] = feature_importance.head(20).to_dict('records')
            
            logger.info("\nRandom Forest - Classification Report:")
            logger.info(classification_report(y_test, y_pred_rf))
        
        # Isolation Forest
        if self.isolation_forest:
            logger.info("Ewaluacja Isolation Forest...")
            y_pred_if = self.isolation_forest.predict(X_test)
            # Konwertuj: -1 (anomalia) -> 1 (phishing), 1 (normal) -> 0 (safe)
            y_pred_if_binary = np.where(y_pred_if == -1, 1, 0)
            
            results['isolation_forest'] = {
                'classification_report': classification_report(y_test, y_pred_if_binary, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred_if_binary).tolist(),
                'predictions': y_pred_if_binary.tolist(),
                'anomaly_scores': self.isolation_forest.score_samples(X_test).tolist()
            }
            
            logger.info("\nIsolation Forest - Classification Report:")
            logger.info(classification_report(y_test, y_pred_if_binary))
        
        return results
    
    def save_models(self, prefix: str = ""):
        """
        Zapisuje wytrenowane modele
        
        Args:
            prefix: Prefiks nazwy pliku
        """
        if prefix:
            prefix = f"{prefix}_"
        
        # Random Forest
        if self.random_forest:
            rf_path = self.models_dir / f"{prefix}random_forest_classifier.joblib"
            joblib.dump(self.random_forest, rf_path)
            logger.info(f"Zapisano Random Forest: {rf_path}")
        
        # Isolation Forest
        if self.isolation_forest:
            if_path = self.models_dir / f"{prefix}isolation_forest_anomaly.joblib"
            joblib.dump(self.isolation_forest, if_path)
            logger.info(f"Zapisano Isolation Forest: {if_path}")
        
        # Scaler
        if self.scaler:
            scaler_path = self.models_dir / f"{prefix}scaler.joblib"
            joblib.dump(self.scaler, scaler_path)
            logger.info(f"Zapisano Scaler: {scaler_path}")
        
        # Feature names
        if self.feature_names:
            features_path = self.models_dir / f"{prefix}feature_names.joblib"
            joblib.dump(self.feature_names, features_path)
            logger.info(f"Zapisano nazwy cech: {features_path}")
    
    def full_training_pipeline(self,
                              X: pd.DataFrame,
                              y: pd.Series,
                              test_size: float = 0.2,
                              hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Pełny pipeline treningu
        
        Args:
            X: Cechy
            y: Etykiety
            test_size: Proporcja zbioru testowego
            hyperparameter_tuning: Czy przeprowadzić tuning
            
        Returns:
            Wyniki ewaluacji
        """
        # Przygotowanie danych
        X_train, X_test, y_train, y_test = self.prepare_data(X, y, test_size)
        
        # Trening modeli
        self.train_random_forest(X_train, y_train, hyperparameter_tuning)
        self.train_isolation_forest(X_train)
        
        # Ewaluacja
        results = self.evaluate(X_test, y_test)
        
        # Zapisz modele
        self.save_models()
        
        return results


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
    
    # Załaduj dane
    logger.info(f"Ładowanie danych z: {args.data}")
    df = pd.read_csv(args.data)
    
    # Rozdziel cechy i etykiety
    y = df[args.target]
    X = df.drop(columns=[args.target])
    
    # Trenuj modele
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

