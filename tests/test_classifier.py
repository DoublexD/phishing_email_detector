"""
Testy klasyfikatora 
"""

import pytest
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from ml_models.predict import EmailClassifier


@pytest.fixture
def mock_classifier():
    """Klasyfikator z zamockowanymi modelami"""
    with patch.object(EmailClassifier, 'load_models'):
        clf = EmailClassifier(models_dir="fake_dir")
    clf.feature_names = ['spf_pass', 'dkim_valid', 'suspicious_keywords_count']
    return clf


@pytest.fixture
def sample_features():
    """Przykładowe cechy"""
    return pd.DataFrame({
        'spf_pass': [1],
        'dkim_valid': [1],
        'suspicious_keywords_count': [0],
    })


@pytest.fixture
def sample_features_series():
    """Przykładowe cechy jako Series"""
    return pd.Series({
        'spf_pass': 1,
        'dkim_valid': 1,
        'suspicious_keywords_count': 0,
    })


class TestAggregation:
    """Testy agregacji predykcji z modeli"""

    def test_rf_phishing_vote_high_confidence(self, mock_classifier):
        """RF głosuje za phishing z confidence >= 0.75 → is_suspicious"""
        models = {
            'random_forest': {
                'prediction': 1,
                'probability': 0.9,
                'is_phishing': True,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert is_suspicious == True
        assert confidence == pytest.approx(0.9)
        assert risk == 'HIGH'

    def test_rf_phishing_vote_low_confidence(self, mock_classifier):
        """RF probability poniżej optimal_threshold (0.5) → nie suspicious"""
        models = {
            'random_forest': {
                'prediction': 0,
                'probability': 0.4,
                'is_phishing': False,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert is_suspicious == False

    def test_rf_safe_vote(self, mock_classifier):
        models = {
            'random_forest': {
                'prediction': 0,
                'probability': 0.1,
                'is_phishing': False,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert is_suspicious is False

    def test_isolation_forest_anomaly_has_confidence(self, mock_classifier):
        """Bug fix: IF anomaly powinien mieć confidence"""
        models = {
            'isolation_forest': {
                'prediction': -1,
                'anomaly_score': -0.5,
                'is_anomaly': True,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert confidence > 0

    def test_isolation_forest_normal_has_confidence(self, mock_classifier):
        """Bug fix: IF normalna predykcja TEŻ powinna mieć confidence (nie pomijać)"""
        models = {
            'isolation_forest': {
                'prediction': 1,
                'anomaly_score': 0.3,
                'is_anomaly': False,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert confidence > 0

    def test_both_models_combined_high_confidence(self, mock_classifier):
        """Oba modele głosują za z wysoką confidence → suspicious"""
        models = {
            'random_forest': {
                'prediction': 1,
                'probability': 0.95,
                'is_phishing': True,
            },
            'isolation_forest': {
                'prediction': -1,
                'anomaly_score': -1.5,
                'is_anomaly': True,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert is_suspicious == True
        assert confidence >= 0.75

    def test_both_models_combined_low_avg(self, mock_classifier):
        """Ważona średnia obu modeli poniżej ensemble_threshold (0.5) → nie suspicious"""
        models = {
            'random_forest': {
                'prediction': 0,
                'probability': 0.35,
                'is_phishing': False,
            },
            'isolation_forest': {
                'prediction': 1,
                'anomaly_score': 0.3,
                'is_anomaly': False,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert is_suspicious == False
        assert 0.0 < confidence <= 1.0

    def test_models_disagree(self, mock_classifier):
        """Modele się nie zgadzają — jeden za, jeden przeciw"""
        models = {
            'random_forest': {
                'prediction': 0,
                'probability': 0.2,
                'is_phishing': False,
            },
            'isolation_forest': {
                'prediction': -1,
                'anomaly_score': -0.3,
                'is_anomaly': True,
            }
        }
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(models)
        assert isinstance(is_suspicious, bool)

    def test_no_models_uses_heuristics(self, mock_classifier, sample_features):
        """Brak modeli ML → fallback na heurystyki"""
        is_suspicious, confidence, risk = mock_classifier._aggregate_predictions(
            {}, sample_features
        )
        assert isinstance(is_suspicious, bool)
        assert 0.0 <= confidence <= 1.0

    def test_confidence_capped_at_1(self, mock_classifier):
        """Confidence nie powinno przekraczać 1.0"""
        models = {
            'random_forest': {
                'prediction': 1,
                'probability': 0.99,
                'is_phishing': True,
            },
            'isolation_forest': {
                'prediction': -1,
                'anomaly_score': -5.0,
                'is_anomaly': True,
            }
        }
        _, confidence, _ = mock_classifier._aggregate_predictions(models)
        assert confidence <= 1.0


class TestHeuristics:
    """Testy klasyfikacji heurystycznej"""

    def test_spf_fail_adds_score(self, mock_classifier):
        features = pd.DataFrame({'spf_fail': [1], 'dkim_invalid': [0],
                                  'from_return_path_mismatch': [0], 'from_reply_to_mismatch': [0],
                                  'suspicious_keywords_count': [0], 'ip_address_url_count': [0],
                                  'shortened_url_count': [0], 'suspicious_tld_count': [0],
                                  'from_has_numbers': [0], 'exclamation_count': [0],
                                  'capital_letter_ratio': [0], 'has_executable': [0]})
        is_suspicious, confidence, risk = mock_classifier._heuristic_classification(features)
        assert confidence > 0

    def test_executable_attachment_high_score(self, mock_classifier):
        features = pd.DataFrame({'spf_fail': [1], 'dkim_invalid': [1],
                                  'from_return_path_mismatch': [1], 'from_reply_to_mismatch': [0],
                                  'suspicious_keywords_count': [5], 'ip_address_url_count': [1],
                                  'shortened_url_count': [0], 'suspicious_tld_count': [0],
                                  'from_has_numbers': [0], 'exclamation_count': [0],
                                  'capital_letter_ratio': [0], 'has_executable': [1]})
        is_suspicious, confidence, risk = mock_classifier._heuristic_classification(features)
        assert is_suspicious is True
        assert risk == 'HIGH'

    def test_clean_email_low_score(self, mock_classifier):
        features = pd.DataFrame({'spf_fail': [0], 'dkim_invalid': [0],
                                  'from_return_path_mismatch': [0], 'from_reply_to_mismatch': [0],
                                  'suspicious_keywords_count': [0], 'ip_address_url_count': [0],
                                  'shortened_url_count': [0], 'suspicious_tld_count': [0],
                                  'from_has_numbers': [0], 'exclamation_count': [0],
                                  'capital_letter_ratio': [0], 'has_executable': [0]})
        is_suspicious, confidence, risk = mock_classifier._heuristic_classification(features)
        assert is_suspicious is False
        assert risk == 'LOW'

    def test_empty_features(self, mock_classifier):
        features = pd.DataFrame()
        is_suspicious, confidence, risk = mock_classifier._heuristic_classification(features)
        assert is_suspicious is False
        assert risk == 'UNKNOWN'


class TestPredict:
    """Testy metody predict"""

    def test_predict_accepts_series(self, mock_classifier, sample_features_series):
        """predict() powinien akceptować zarówno DataFrame jak i Series"""
        mock_classifier.random_forest = None
        mock_classifier.isolation_forest = None
        mock_classifier.scaler = None

        result = mock_classifier.predict(sample_features_series)
        assert 'is_suspicious' in result
        assert 'confidence' in result
        assert 'risk_level' in result

    def test_predict_with_missing_features(self, mock_classifier):
        """Brakujące cechy powinny być uzupełnione zerami"""
        mock_classifier.random_forest = None
        mock_classifier.isolation_forest = None
        mock_classifier.scaler = None

        features = pd.Series({'spf_pass': 1})
        result = mock_classifier.predict(features)
        assert result is not None

    def test_predict_with_mock_rf(self, mock_classifier, sample_features):
        """predict z mock Random Forest"""
        rf = Mock()
        rf.predict.return_value = np.array([1])
        rf.predict_proba.return_value = np.array([[0.2, 0.8]])
        mock_classifier.random_forest = rf
        mock_classifier.isolation_forest = None
        mock_classifier.scaler = None

        result = mock_classifier.predict(sample_features)
        assert result['models']['random_forest']['is_phishing'] is True
        assert result['models']['random_forest']['probability'] == pytest.approx(0.8)


class TestRecommendation:
    """Testy mapowania ryzyka na rekomendację"""

    def test_high_risk(self, mock_classifier):
        assert mock_classifier._get_recommendation('HIGH') == 'QUARANTINE'

    def test_medium_risk(self, mock_classifier):
        assert mock_classifier._get_recommendation('MEDIUM') == 'FLAG'

    def test_low_risk(self, mock_classifier):
        assert mock_classifier._get_recommendation('LOW') == 'ALLOW'

    def test_unknown_risk(self, mock_classifier):
        assert mock_classifier._get_recommendation('UNKNOWN') == 'REVIEW'


class TestBatchPredict:
    """Testy predykcji wsadowej"""

    def test_batch_predict(self, mock_classifier, sample_features):
        mock_classifier.random_forest = None
        mock_classifier.isolation_forest = None
        mock_classifier.scaler = None

        batch = pd.concat([sample_features, sample_features], ignore_index=True)
        results = mock_classifier.predict_batch(batch)
        assert len(results) == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
