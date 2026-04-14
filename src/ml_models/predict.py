"""
Email Classifier
Klasyfikacja wiadomości e-mail przy użyciu wytrenowanych modeli
"""

import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class EmailClassifier:
    """Klasa do klasyfikacji wiadomości e-mail"""
    
    def __init__(self, models_dir: str = "models", prefix: str = ""):
        """
        Inicjalizacja klasyfikatora
        
        Args:
            models_dir: Katalog z modelami
            prefix: Prefiks nazw plików modeli
        """
        self.models_dir = Path(models_dir)
        self.prefix = f"{prefix}_" if prefix else ""
        
        self.random_forest = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
        
        self.load_models()
    
    def load_models(self):
        """Ładuje wytrenowane modele"""
        try:
            # Random Forest
            rf_path = self.models_dir / f"{self.prefix}random_forest_classifier.joblib"
            if rf_path.exists():
                self.random_forest = joblib.load(rf_path)
                logger.info(f"Załadowano Random Forest z: {rf_path}")
            else:
                logger.warning(f"Brak modelu Random Forest: {rf_path}")
            
            # Isolation Forest
            if_path = self.models_dir / f"{self.prefix}isolation_forest_anomaly.joblib"
            if if_path.exists():
                self.isolation_forest = joblib.load(if_path)
                logger.info(f"Załadowano Isolation Forest z: {if_path}")
            else:
                logger.warning(f"Brak modelu Isolation Forest: {if_path}")
            
            # Scaler
            scaler_path = self.models_dir / f"{self.prefix}scaler.joblib"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Załadowano Scaler z: {scaler_path}")
            else:
                logger.warning(f"Brak scalera: {scaler_path}")
            
            # Feature names
            features_path = self.models_dir / f"{self.prefix}feature_names.joblib"
            if features_path.exists():
                self.feature_names = joblib.load(features_path)
                logger.info(f"Załadowano nazwy cech: {features_path}")
            else:
                logger.warning(f"Brak nazw cech: {features_path}")
                
        except Exception as e:
            logger.error(f"Błąd ładowania modeli: {e}")
            raise
    
    def predict(self, features: pd.DataFrame) -> Dict[str, Any]:
        """
        Predykcja dla pojedynczej wiadomości
        
        Args:
            features: Cechy wiadomości (DataFrame lub Series)
            
        Returns:
            Słownik z wynikami predykcji
        """
        # Konwertuj Series na DataFrame
        if isinstance(features, pd.Series):
            features = features.to_frame().T
        
        # Zachowaj oryginalne cechy dla heurystyk
        original_features = features.copy()
        
        # Upewnij się, że mamy wszystkie potrzebne cechy
        if self.feature_names:
            missing_features = set(self.feature_names) - set(features.columns)
            if missing_features:
                logger.warning(f"Brakujące cechy: {missing_features}")
                # Dodaj brakujące cechy z wartościami 0
                for feature in missing_features:
                    features[feature] = 0
            
            # Uporządkuj kolumny zgodnie z trenowaniem
            features = features[self.feature_names]
        
        # Skaluj cechy
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
        
        # Predykcja Random Forest
        if self.random_forest:
            rf_pred = self.random_forest.predict(features_scaled)[0]
            rf_proba = self.random_forest.predict_proba(features_scaled)[0]
            
            result['models']['random_forest'] = {
                'prediction': int(rf_pred),
                'probability': float(rf_proba[1]),  # Prawdopodobieństwo klasy "phishing"
                'is_phishing': bool(rf_pred == 1)
            }
            
            if rf_pred == 1:
                result['explanation'].append(
                    f"Model Random Forest wykrył phishing (prawdopodobieństwo: {rf_proba[1]:.2%})"
                )
        
        # Predykcja Isolation Forest
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
        
        # Agregacja wyników
        result['is_suspicious'], result['confidence'], result['risk_level'] = \
            self._aggregate_predictions(result['models'], original_features)
        
        # Rekomendacja
        result['recommendation'] = self._get_recommendation(result['risk_level'])
        
        return result
    
    def predict_batch(self, features_batch: pd.DataFrame) -> list:
        """
        Predykcja dla wielu wiadomości
        
        Args:
            features_batch: DataFrame z cechami wielu wiadomości
            
        Returns:
            Lista wyników predykcji
        """
        results = []
        
        for idx in range(len(features_batch)):
            features = features_batch.iloc[idx:idx+1]
            result = self.predict(features)
            results.append(result)
        
        return results
    
    def _aggregate_predictions(self, models: Dict[str, Any], features: pd.DataFrame = None) -> Tuple[bool, float, str]:
        """
        Agreguje predykcje z różnych modeli lub używa heurystyk
        
        Args:
            models: Wyniki z poszczególnych modeli
            features: Cechy e-maila (używane gdy brak modeli ML)
            
        Returns:
            (is_suspicious, confidence, risk_level)
        """
        votes = []
        confidences = []
        
        # Random Forest
        if 'random_forest' in models:
            rf = models['random_forest']
            if rf['is_phishing']:
                votes.append(1)
                confidences.append(rf['probability'])
            else:
                votes.append(0)
                confidences.append(1 - rf['probability'])
        
        # Isolation Forest
        if 'isolation_forest' in models:
            if_model = models['isolation_forest']
            if if_model['is_anomaly']:
                votes.append(1)
                # Konwertuj anomaly score na pewność (heurystyka)
                confidence = min(abs(if_model['anomaly_score']) / 2, 1.0)
                confidences.append(confidence)
            else:
                votes.append(0)
        
        # Jeśli nie ma żadnych modeli - użyj heurystyk
        if not votes and features is not None:
            return self._heuristic_classification(features)
        
        # Średnia pewność
        avg_confidence = np.mean(confidences) if confidences else 0.0

        # Poziom ryzyka
        if avg_confidence >= 0.8:
            risk_level = 'HIGH'
        elif avg_confidence >= 0.5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # is_suspicious: podejrzany jeśli pewność >= 75% (wyższy próg = mniej fałszywych alarmów)
        majority_vote = sum(votes) > len(votes) / 2
        is_suspicious = majority_vote and avg_confidence >= 0.75

        return is_suspicious, float(avg_confidence), risk_level
    
    def _heuristic_classification(self, features: pd.DataFrame) -> Tuple[bool, float, str]:
        """
        Klasyfikacja oparta na heurystykach (gdy brak modeli ML)
        
        Args:
            features: Cechy e-maila
            
        Returns:
            (is_suspicious, confidence, risk_level)
        """
        if features.empty:
            return False, 0.0, 'UNKNOWN'
        
        # Pobierz pierwszą (i jedyną) linię
        feat = features.iloc[0]
        
        # Punkty podejrzanych wskaźników (0-100)
        suspicion_score = 0
        reasons = []
        
        # 1. Autentykacja (30 punktów)
        if feat.get('spf_fail', 0) == 1:
            suspicion_score += 15
            reasons.append("SPF failed")
        if feat.get('dkim_invalid', 0) == 1:
            suspicion_score += 15
            reasons.append("DKIM invalid")
        
        # 2. Niezgodności nagłówków (25 punktów)
        if feat.get('from_return_path_mismatch', 0) == 1:
            suspicion_score += 15
            reasons.append("From/Return-Path mismatch")
        if feat.get('reply_to_different_domain', 0) == 1:
            suspicion_score += 10
            reasons.append("Reply-To different domain")
        
        # 3. Podejrzane słowa (20 punktów)
        suspicious_keywords = feat.get('suspicious_keywords_count', 0)
        if suspicious_keywords >= 3:
            suspicion_score += 20
            reasons.append(f"{int(suspicious_keywords)} suspicious keywords")
        elif suspicious_keywords >= 1:
            suspicion_score += 10
            reasons.append(f"{int(suspicious_keywords)} suspicious keywords")
        
        # 4. Podejrzane URL-e (25 punktów)
        if feat.get('ip_address_url_count', 0) > 0:
            suspicion_score += 15
            reasons.append("IP address in URL")
        if feat.get('shortened_url_count', 0) > 0:
            suspicion_score += 10
            reasons.append("Shortened URLs")
        
        # 5. Podejrzana domena (15 punktów)
        if feat.get('sender_domain_suspicious_tld', 0) == 1:
            suspicion_score += 10
            reasons.append("Suspicious TLD")
        if feat.get('domain_numbers_count', 0) > 2:
            suspicion_score += 5
            reasons.append("Numbers in domain")
        
        # 6. Nadmierna urgentność (10 punktów)
        if feat.get('exclamation_count', 0) >= 3:
            suspicion_score += 5
            reasons.append("Multiple exclamation marks")
        if feat.get('all_caps_subject', 0) == 1:
            suspicion_score += 5
            reasons.append("ALL CAPS subject")
        
        # 7. Załączniki wykonywalne (bonus)
        if feat.get('has_executable_attachment', 0) == 1:
            suspicion_score += 20
            reasons.append("Executable attachment")
        
        # Ogranicz do 100
        suspicion_score = min(suspicion_score, 100)
        
        # Określ klasyfikację
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
        
        Args:
            risk_level: Poziom ryzyka
            
        Returns:
            Rekomendowana akcja
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
        
        Args:
            top_n: Liczba najważniejszych cech
            
        Returns:
            DataFrame z ważnością cech
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
        
        Args:
            features: Cechy wiadomości
            result: Wynik predykcji
            
        Returns:
            Lista wyjaśnień
        """
        explanations = result.get('explanation', []).copy()
        
        # Dodaj wyjaśnienia na podstawie cech
        if isinstance(features, pd.Series):
            features = features.to_dict()
        elif isinstance(features, pd.DataFrame):
            features = features.iloc[0].to_dict()
        
        # Sprawdź kluczowe cechy
        if features.get('spf_fail', 0) == 1:
            explanations.append("⚠️ Weryfikacja SPF nieudana")
        
        if features.get('dkim_invalid', 0) == 1:
            explanations.append("⚠️ Nieprawidłowy podpis DKIM")
        
        if features.get('from_return_path_mismatch', 0) == 1:
            explanations.append("⚠️ Niezgodność między From a Return-Path")
        
        if features.get('suspicious_keywords_count', 0) > 3:
            explanations.append(f"⚠️ Wykryto {features['suspicious_keywords_count']} podejrzanych słów kluczowych")
        
        if features.get('ip_address_url_count', 0) > 0:
            explanations.append("⚠️ URL zawiera adres IP zamiast domeny")
        
        if features.get('has_executable', 0) == 1:
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
    
    # Załaduj cechy
    logger.info(f"Ładowanie cech z: {args.features}")
    features_df = pd.read_csv(args.features)
    
    # Inicjalizuj klasyfikator
    classifier = EmailClassifier(models_dir=args.models_dir)
    
    # Predykcje
    results = classifier.predict_batch(features_df)
    
    # Wyświetl wyniki
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
    
    # Zapisz wyniki
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Zapisano wyniki do: {args.output}")


if __name__ == '__main__':
    from ..utils.helpers import setup_logging
    setup_logging()
    main()

