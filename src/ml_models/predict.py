"""
Email Classifier
Klasyfikacja wiadomości e-mail przy użyciu wytrenowanych modeli
"""

import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)


class EmailClassifier:
    """Klasa do klasyfikacji wiadomości"""
    
    def __init__(self, models_dir: str = "models", prefix: str = ""):
        """
        Inicjalizacja klasyfikatora

        """
        self.models_dir = Path(models_dir)
        self.prefix = f"{prefix}_" if prefix else ""
        
        self.random_forest = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
        
        self.load_models()
    
    def load_models(self):
        """Ładuje wytrenowane modele i konfigurację"""
        try:
            rf_path = self.models_dir / f"{self.prefix}random_forest_classifier.joblib"
            if rf_path.exists():
                self.random_forest = joblib.load(rf_path)
                logger.info(f"Załadowano Random Forest z: {rf_path}")
            else:
                logger.warning(f"Brak modelu Random Forest: {rf_path}")

            if_path = self.models_dir / f"{self.prefix}isolation_forest_anomaly.joblib"
            if if_path.exists():
                self.isolation_forest = joblib.load(if_path)
                logger.info(f"Załadowano Isolation Forest z: {if_path}")
            else:
                logger.warning(f"Brak modelu Isolation Forest: {if_path}")

            scaler_path = self.models_dir / f"{self.prefix}scaler.joblib"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Załadowano Scaler z: {scaler_path}")
            else:
                logger.warning(f"Brak scalera: {scaler_path}")

            features_path = self.models_dir / f"{self.prefix}feature_names.joblib"
            if features_path.exists():
                self.feature_names = joblib.load(features_path)
                logger.info(f"Załadowano nazwy cech: {features_path}")
            else:
                logger.warning(f"Brak nazw cech: {features_path}")

            config_path = self.models_dir / f"{self.prefix}model_config.joblib"
            if config_path.exists():
                self.model_config = joblib.load(config_path)
                logger.info(f"Załadowano konfigurację: {self.model_config}")
            else:
                self.model_config = {
                    'optimal_threshold': 0.5,
                    'ensemble_weights': {'rf': 0.75, 'if': 0.25},
                    'ensemble_threshold': 0.5,
                }
                
        except Exception as e:
            logger.error(f"Błąd ładowania modeli: {e}")
            raise
    
    def predict(self, features: Union[pd.DataFrame, pd.Series]) -> Dict[str, Any]:
        """
        Predykcja dla pojedynczej wiadomości, zwraca słownik z wynikami predykcji

        """
        if isinstance(features, pd.Series):
            features = features.to_frame().T

        original_features = features.copy()

        if self.feature_names:
            missing_features = set(self.feature_names) - set(features.columns)
            if missing_features:
                logger.warning(f"Brakujące cechy: {missing_features}")
                for feature in missing_features:
                    features[feature] = 0

            features = features[self.feature_names]

        if self.scaler:
            features_scaled = self.scaler.transform(features)
            features_scaled = pd.DataFrame(features_scaled, columns=features.columns)
        else:
            features_scaled = features
        
        result = {
            'is_suspicious': False,
            'confidence': 0.0,
            'risk_level': 'LOW',
            'models': {},
            'recommendation': 'ALLOW',
            'explanation': []
        }

        if self.random_forest:
            rf_proba = self.random_forest.predict_proba(features_scaled)[0]
            optimal_threshold = getattr(self, 'model_config', {}).get('optimal_threshold', 0.5)
            rf_pred = int(rf_proba[1] >= optimal_threshold)
            
            result['models']['random_forest'] = {
                'prediction': rf_pred,
                'probability': float(rf_proba[1]),
                'is_phishing': bool(rf_pred == 1),
                'threshold_used': optimal_threshold,
            }
            
            if rf_pred == 1:
                result['explanation'].append(
                    f"Model Random Forest wykrył phishing "
                    f"(prawdopodobieństwo: {rf_proba[1]:.2%}, próg: {optimal_threshold:.2f})"
                )

        if self.isolation_forest:
            if_pred = self.isolation_forest.predict(features_scaled)[0]
            if_score = self.isolation_forest.score_samples(features_scaled)[0]
            
            result['models']['isolation_forest'] = {
                'prediction': int(if_pred),
                'anomaly_score': float(if_score),
                'is_anomaly': bool(if_pred == -1)
            }
            
            if if_pred == -1:
                result['explanation'].append(
                    f"Model Isolation Forest wykrył anomalię (score: {if_score:.4f})"
                )

        result['is_suspicious'], result['confidence'], result['risk_level'] = \
            self._aggregate_predictions(result['models'], original_features)

        result['recommendation'] = self._get_recommendation(result['risk_level'])
        
        return result
    
    def predict_batch(self, features_batch: pd.DataFrame) -> list:
        """
        Predykcja dla wielu wiadomości

        """
        results = []
        
        for idx in range(len(features_batch)):
            features = features_batch.iloc[idx:idx+1]
            result = self.predict(features)
            results.append(result)
        
        return results
    
    def _aggregate_predictions(self, models: Dict[str, Any], features: Optional[pd.DataFrame] = None) -> Tuple[bool, float, str]:
        """
        Funkcja łączy ocenę dwóch modeli w jeden końcowy wynik ryzyka dla e-maila.(RF=0.75, IF=0.25),
    
        """
        if not models and features is not None:
            return self._heuristic_classification(features)
        
        config = getattr(self, 'model_config', {})
        weights = config.get('ensemble_weights', {'rf': 0.75, 'if': 0.25})
        ensemble_threshold = config.get('ensemble_threshold', 0.5)
        optimal_threshold = config.get('optimal_threshold', 0.5)
        
        rf_proba = None
        if_proba = None
        
        if 'random_forest' in models:
            rf_proba = models['random_forest']['probability']
        
        if 'isolation_forest' in models:
            raw_score = models['isolation_forest']['anomaly_score']
            if_proba = max(0.0, min(1.0, 0.5 - raw_score))

        if rf_proba is not None and if_proba is not None:
            combined = weights['rf'] * rf_proba + weights['if'] * if_proba
            is_suspicious = combined >= ensemble_threshold
            confidence = float(combined)
        elif rf_proba is not None:
            is_suspicious = rf_proba >= optimal_threshold
            confidence = float(rf_proba)
        elif if_proba is not None:
            is_suspicious = if_proba >= 0.5
            confidence = float(if_proba)
        else:
            if features is not None:
                return self._heuristic_classification(features)
            return False, 0.0, 'UNKNOWN'
        
        if confidence >= 0.8:
            risk_level = 'HIGH'
        elif confidence >= 0.5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return bool(is_suspicious), confidence, risk_level
    
    def _heuristic_classification(self, features: pd.DataFrame) -> Tuple[bool, float, str]:
        """
        Klasyfikacja oparta na heurystykach w razie braku załadowanych modeli ML
        
        """
        if features.empty:
            return False, 0.0, 'UNKNOWN'

        feat = features.iloc[0]

        suspicion_score = 0
        reasons = []

        if feat.get('spf_fail', 0) == 1:
            suspicion_score += 15
            reasons.append("SPF failed")
        if feat.get('dkim_invalid', 0) == 1:
            suspicion_score += 15
            reasons.append("DKIM invalid")

        if feat.get('from_return_path_mismatch', 0) == 1:
            suspicion_score += 15
            reasons.append("From/Return-Path mismatch")
        if feat.get('from_reply_to_mismatch', 0) == 1:
            suspicion_score += 10
            reasons.append("Reply-To different domain")

        suspicious_keywords = feat.get('suspicious_keywords_count', 0)
        if suspicious_keywords >= 3:
            suspicion_score += 20
            reasons.append(f"{int(suspicious_keywords)} suspicious keywords")
        elif suspicious_keywords >= 1:
            suspicion_score += 10
            reasons.append(f"{int(suspicious_keywords)} suspicious keywords")

        if feat.get('ip_address_url_count', 0) > 0:
            suspicion_score += 15
            reasons.append("IP address in URL")
        if feat.get('shortened_url_count', 0) > 0:
            suspicion_score += 10
            reasons.append("Shortened URLs")

        if feat.get('suspicious_tld_count', 0) > 0:
            suspicion_score += 10
            reasons.append("Suspicious TLD")
        if feat.get('from_has_numbers', 0) == 1:
            suspicion_score += 5
            reasons.append("Numbers in sender address")

        if feat.get('exclamation_count', 0) >= 3:
            suspicion_score += 5
            reasons.append("Multiple exclamation marks")
        if feat.get('capital_letter_ratio', 0) > 0.5:
            suspicion_score += 5
            reasons.append("High capital letter ratio")

        if feat.get('has_executable', 0) == 1:
            suspicion_score += 20
            reasons.append("Executable attachment")

        suspicion_score = min(suspicion_score, 100)

        confidence = suspicion_score / 100.0
        
        logger.info(f"Heuristic classification: score={suspicion_score}, reasons={reasons}")
        
        if suspicion_score >= 60:
            return True, confidence, 'HIGH'
        elif suspicion_score >= 30:
            return True, confidence, 'MEDIUM'
        else:
            return False, confidence, 'LOW'
    
    def _get_recommendation(self, risk_level: str) -> str:
        """
        Zwraca rekomendację na podstawie poziomu ryzyka
        """
        recommendations = {
            'HIGH': 'QUARANTINE',
            'MEDIUM': 'FLAG',
            'LOW': 'ALLOW',
            'UNKNOWN': 'REVIEW'
        }
        return recommendations.get(risk_level, 'REVIEW')
    
    def get_feature_importance(self, top_n: int = 20) -> Optional[pd.DataFrame]:
        """
        Zwraca najważniejsze cechy z modelu Random Forest
        """
        if not self.random_forest or not self.feature_names:
            return None
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.random_forest.feature_importances_
        }).sort_values('importance', ascending=False).head(top_n)
        
        return importance_df
    
    def explain_prediction(self, 
                          features: pd.DataFrame,
                          result: Dict[str, Any]) -> list:
        """
        Generuje wyjaśnienie predykcji
        """
        explanations = result.get('explanation', []).copy()

        feat: Dict[str, Any]
        if isinstance(features, pd.Series):
            feat = features.to_dict()
        elif isinstance(features, pd.DataFrame):
            feat = features.iloc[0].to_dict()
        else:
            feat = dict(features)

        if feat.get('spf_fail', 0) == 1:
            explanations.append("⚠️ Weryfikacja SPF nieudana")
        
        if feat.get('dkim_invalid', 0) == 1:
            explanations.append("⚠️ Nieprawidłowy podpis DKIM")
        
        if feat.get('from_return_path_mismatch', 0) == 1:
            explanations.append("⚠️ Niezgodność między From a Return-Path")
        
        if feat.get('suspicious_keywords_count', 0) > 3:
            explanations.append(f"⚠️ Wykryto {feat['suspicious_keywords_count']} podejrzanych słów kluczowych")
        
        if feat.get('ip_address_url_count', 0) > 0:
            explanations.append("⚠️ URL zawiera adres IP zamiast domeny")
        
        if feat.get('has_executable', 0) == 1:
            explanations.append("⚠️ Wiadomość zawiera plik wykonywalny")
        
        return explanations


def main():
    """Główna funkcja do testowania klasyfikatora"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Klasyfikacja wiadomości e-mail')
    parser.add_argument('--features', type=str, required=True, help='Ścieżka do pliku CSV z cechami')
    parser.add_argument('--models-dir', type=str, default='models', help='Katalog z modelami')
    parser.add_argument('--output', type=str, help='Ścieżka do pliku wyjściowego')
    
    args = parser.parse_args()

    logger.info(f"Ładowanie cech z: {args.features}")
    features_df = pd.read_csv(args.features)

    classifier = EmailClassifier(models_dir=args.models_dir)

    results = classifier.predict_batch(features_df)

    for i, result in enumerate(results):
        print(f"\n=== Wiadomość {i+1} ===")
        print(f"Podejrzana: {result['is_suspicious']}")
        print(f"Pewność: {result['confidence']:.2%}")
        print(f"Poziom ryzyka: {result['risk_level']}")
        print(f"Rekomendacja: {result['recommendation']}")
        if result['explanation']:
            print("Wyjaśnienia:")
            for explanation in result['explanation']:
                print(f"  - {explanation}")

    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Zapisano wyniki do: {args.output}")


if __name__ == '__main__':
    from ..utils.helpers import setup_logging
    setup_logging()
    main()

