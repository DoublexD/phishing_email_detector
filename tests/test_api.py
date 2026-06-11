"""
Testy dla REST API
"""

import pytest
import sys
import base64
import threading
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


@pytest.fixture
def client():
    """Fixture zwracający test client z zamockowanymi komponentami"""
    with patch('api.app.EmailParser') as MockParser, \
         patch('api.app.HeaderAnalyzer') as MockAnalyzer, \
         patch('api.app.SPFChecker'), \
         patch('api.app.DKIMChecker'), \
         patch('api.app.DMARCChecker'), \
         patch('api.app.FeatureExtractor') as MockExtractor, \
         patch('api.app.EmailClassifier') as MockClassifier, \
         patch('api.app.ModelManager') as MockManager, \
         patch('api.app.setup_logging') as MockLog, \
         patch('api.app.load_config', return_value={}), \
         patch('api.app._load_persisted_alerts', return_value=[]), \
         patch('api.app._load_persisted_stats', return_value={
             'total_analyzed': 0, 'suspicious_detected': 0,
             'safe_emails': 0, 'last_updated': None
         }):

        MockLog.return_value = MagicMock()
        MockManager.return_value.get_model_stats.return_value = {}

        import importlib
        import api.app as app_module
        importlib.reload(app_module)

        return TestClient(app_module.app)


@pytest.fixture
def mock_app_module():
    """Zwraca moduł app po reload z mockami"""
    with patch('api.app.EmailParser') as MockParser, \
         patch('api.app.HeaderAnalyzer') as MockAnalyzer, \
         patch('api.app.SPFChecker'), \
         patch('api.app.DKIMChecker'), \
         patch('api.app.DMARCChecker'), \
         patch('api.app.FeatureExtractor') as MockExtractor, \
         patch('api.app.EmailClassifier') as MockClassifier, \
         patch('api.app.ModelManager') as MockManager, \
         patch('api.app.setup_logging') as MockLog, \
         patch('api.app.load_config', return_value={}), \
         patch('api.app._load_persisted_alerts', return_value=[]), \
         patch('api.app._load_persisted_stats', return_value={
             'total_analyzed': 0, 'suspicious_detected': 0,
             'safe_emails': 0, 'last_updated': None
         }):

        MockLog.return_value = MagicMock()
        MockManager.return_value.get_model_stats.return_value = {}

        import importlib
        import api.app as app_module
        importlib.reload(app_module)

        yield app_module


@pytest.fixture
def sample_email_request():
    return {
        "email_string": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody",
        "analyze_authentication": True
    }


class TestBasicEndpoints:
    """Testy podstawowych endpointów"""

    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.0"

    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "models_loaded" in data

    def test_stats(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_analyzed" in data
        assert "detection_rate" in data

    def test_alerts_returns_list(self, client):
        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert isinstance(data["alerts"], list)

    def test_models_info(self, client):
        response = client.get("/api/models")
        assert response.status_code == 200
        data = response.json()
        assert "loaded" in data


class TestAnalyzeEndpoint:
    """Testy endpointu analizy"""

    @patch('api.app.email_parser')
    @patch('api.app.header_analyzer')
    @patch('api.app.spf_checker')
    @patch('api.app.dkim_checker')
    @patch('api.app.dmarc_checker')
    @patch('api.app.feature_extractor')
    @patch('api.app.classifier')
    def test_analyze_safe_email(self, mock_clf, mock_fe, mock_dmarc,
                                 mock_dkim, mock_spf, mock_ha, mock_ep, client):
        mock_ep.parse_email_string.return_value = {
            'from': {'email': 'sender@example.com'},
            'to': [{'email': 'r@example.com'}],
            'subject': 'Test',
            'body': {'plain': 'Hello', 'html': ''}
        }
        mock_ha.analyze.return_value = {
            'from_mismatch': False, 'reply_to_mismatch': False
        }
        mock_spf.check_from_email_data.return_value = {'result': 'pass', 'valid': True}
        mock_dkim.check_from_email_data.return_value = {'result': 'pass', 'valid': True}
        mock_dmarc.check_from_email_data.return_value = {'valid': True, 'record': 'v=DMARC1; p=reject'}
        mock_fe.extract_features.return_value = pd.Series({'spf_pass': 1})
        mock_clf.predict.return_value = {
            'is_suspicious': False, 'confidence': 0.1,
            'risk_level': 'LOW', 'recommendation': 'ALLOW', 'explanation': []
        }

        response = client.post("/api/analyze", json={
            "email_string": "From: sender@example.com\nSubject: Test\n\nBody",
            "analyze_authentication": True
        })
        assert response.status_code == 200
        data = response.json()
        assert data["is_suspicious"] is False
        assert data["risk_level"] == "LOW"

    def test_missing_email_data(self, client):
        """400 gdy brak danych e-maila"""
        response = client.post("/api/analyze", json={
            "analyze_authentication": True
        })
        assert response.status_code == 400

    def test_invalid_base64(self, client):
        """400 dla nieprawidłowego base64"""
        response = client.post("/api/analyze", json={
            "raw_email": "!!!not-valid-base64!!!",
            "analyze_authentication": False
        })
        assert response.status_code == 400

    def test_payload_too_large(self, client):
        """413 gdy e-mail jest za duży"""
        huge_email = "A" * (11 * 1024 * 1024)
        response = client.post("/api/analyze", json={
            "email_string": huge_email,
            "analyze_authentication": False
        })
        assert response.status_code == 413

    def test_payload_too_large_base64(self, client):
        """413 dla za dużego raw_email base64"""
        huge_b64 = "A" * (11 * 1024 * 1024)
        response = client.post("/api/analyze", json={
            "raw_email": huge_b64,
            "analyze_authentication": False
        })
        assert response.status_code == 413

    @patch('api.app.email_parser')
    def test_error_500_no_leak(self, mock_parser, client):
        """Bug fix: 500 nie powinno ujawniać szczegółów wewnętrznego błędu"""
        mock_parser.parse_email_string.side_effect = RuntimeError("SECRET: /internal/path/db.sqlite")

        response = client.post("/api/analyze", json={
            "email_string": "From: test@test.com\nSubject: X\n\nBody",
            "analyze_authentication": False
        })
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "SECRET" not in detail
        assert "/internal/path" not in detail

    def test_invalid_json(self, client):
        response = client.post(
            "/api/analyze",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


class TestAlertsManagement:
    """Testy zarządzania alertami"""

    def test_get_nonexistent_alert(self, client):
        response = client.get("/api/alerts/NONEXISTENT_ID")
        assert response.status_code == 404

    def test_delete_nonexistent_alert(self, client):
        response = client.delete("/api/alerts/NONEXISTENT_ID")
        assert response.status_code == 404

    def test_alerts_limit_validation(self, client):
        """Bug fix: limit powinien być walidowany (1-500)"""
        response = client.get("/api/alerts?limit=0")
        assert response.status_code == 422

        response = client.get("/api/alerts?limit=501")
        assert response.status_code == 422

        response = client.get("/api/alerts?limit=100")
        assert response.status_code == 200

    def test_alerts_risk_filter(self, client):
        response = client.get("/api/alerts?risk_level=HIGH")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["alerts"], list)


class TestFeatureImportance:
    """Testy feature importance"""

    @patch('api.app.classifier')
    def test_feature_importance_ok(self, mock_clf, client):
        mock_clf.get_feature_importance.return_value = pd.DataFrame({
            'feature': ['spf_pass', 'dkim_valid'],
            'importance': [0.5, 0.3]
        })
        response = client.get("/api/feature-importance")
        assert response.status_code == 200
        assert "features" in response.json()

    @patch('api.app.classifier')
    def test_feature_importance_no_model(self, mock_clf, client):
        mock_clf.get_feature_importance.return_value = None
        response = client.get("/api/feature-importance")
        assert response.status_code == 404


class TestIMAPEndpoints:
    """Testy endpointów IMAP"""

    def test_imap_status(self, client):
        response = client.get("/api/imap/status")
        assert response.status_code == 200
        data = response.json()
        assert "active" in data
        assert "configured" in data

    @patch('api.app.imap_monitor_active', False)
    @patch('api.app.config', {})
    def test_imap_start_without_config(self, client):
        """Brak konfiguracji IMAP → 400"""
        import api.app as app_module
        original_active = app_module.imap_monitor_active
        original_config = app_module.config
        app_module.imap_monitor_active = False
        app_module.config = {}
        try:
            response = client.post("/api/imap/start")
            assert response.status_code == 400
        finally:
            app_module.imap_monitor_active = original_active
            app_module.config = original_config

    def test_imap_stop_not_running(self, client):
        response = client.post("/api/imap/stop")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_running"


class TestThreadSafety:
    """Testy thread-safety statystyk i alertów"""

    def test_update_statistics_thread_safe(self, mock_app_module):
        """Współbieżne aktualizacje statystyk nie powinny tracić danych"""
        module = mock_app_module
        module.statistics = {
            'total_analyzed': 0, 'suspicious_detected': 0,
            'safe_emails': 0, 'last_updated': None
        }

        errors = []
        n_threads = 10
        n_per_thread = 50

        def update_many(is_suspicious):
            try:
                for _ in range(n_per_thread):
                    module.update_statistics(is_suspicious)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=update_many, args=(i % 2 == 0,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert module.statistics['total_analyzed'] == n_threads * n_per_thread

    def test_save_alert_thread_safe(self, mock_app_module):
        """Współbieżne dodawanie alertów nie powinno tracić danych"""
        module = mock_app_module
        module.alerts = []

        errors = []
        n_threads = 10

        def add_alert(idx):
            try:
                module.save_alert(
                    f"TEST_{idx}",
                    {'from': {'email': 'test@test.com'}, 'to': [], 'subject': 'T'},
                    {'risk_level': 'HIGH', 'confidence': 0.9, 'recommendation': 'QUARANTINE'},
                    None,
                    ['SPF_FAIL']
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_alert, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(module.alerts) == n_threads


class TestSpoofingIndicators:
    """Testy logiki wskaźników spoofingu"""

    @patch('api.app.email_parser')
    @patch('api.app.header_analyzer')
    @patch('api.app.spf_checker')
    @patch('api.app.dkim_checker')
    @patch('api.app.dmarc_checker')
    @patch('api.app.feature_extractor')
    @patch('api.app.classifier')
    def test_spf_fail_is_strong_indicator(self, mock_clf, mock_fe, mock_dmarc,
                                          mock_dkim, mock_spf, mock_ha, mock_ep, client):
        """SPF_FAIL powinien być silnym wskaźnikiem i wymuszać is_suspicious=True"""
        mock_ep.parse_email_string.return_value = {
            'from': {'email': 's@example.com'}, 'to': [], 'subject': 'T',
            'body': {'plain': '', 'html': ''}
        }
        mock_ha.analyze.return_value = {'from_mismatch': False, 'reply_to_mismatch': False}
        mock_spf.check_from_email_data.return_value = {'result': 'fail', 'valid': False}
        mock_dkim.check_from_email_data.return_value = {'result': 'pass', 'valid': True}
        mock_dmarc.check_from_email_data.return_value = {'valid': True, 'record': 'v=DMARC1; p=none'}
        mock_fe.extract_features.return_value = pd.Series({'spf_fail': 1})
        mock_clf.predict.return_value = {
            'is_suspicious': False, 'confidence': 0.3,
            'risk_level': 'LOW', 'recommendation': 'ALLOW', 'explanation': []
        }

        response = client.post("/api/analyze", json={
            "email_string": "From: s@example.com\nSubject: T\n\nBody",
            "analyze_authentication": True
        })
        data = response.json()
        assert data["is_suspicious"] is True
        assert "SPF_FAIL" in data["spoofing_indicators"]

    @patch('api.app.email_parser')
    @patch('api.app.header_analyzer')
    @patch('api.app.spf_checker')
    @patch('api.app.dkim_checker')
    @patch('api.app.dmarc_checker')
    @patch('api.app.feature_extractor')
    @patch('api.app.classifier')
    def test_missing_dkim_is_informational_only(self, mock_clf, mock_fe, mock_dmarc,
                                                  mock_dkim, mock_spf, mock_ha, mock_ep, client):
        """DKIM_NONE powinien być informacyjny — nie wymuszać is_suspicious"""
        mock_ep.parse_email_string.return_value = {
            'from': {'email': 's@example.com'}, 'to': [], 'subject': 'T',
            'body': {'plain': '', 'html': ''}
        }
        mock_ha.analyze.return_value = {'from_mismatch': False, 'reply_to_mismatch': False}
        mock_spf.check_from_email_data.return_value = {'result': 'pass', 'valid': True}
        mock_dkim.check_from_email_data.return_value = {'result': 'none', 'valid': False}
        mock_dmarc.check_from_email_data.return_value = {'valid': False}
        mock_fe.extract_features.return_value = pd.Series({'spf_pass': 1})
        mock_clf.predict.return_value = {
            'is_suspicious': False, 'confidence': 0.1,
            'risk_level': 'LOW', 'recommendation': 'ALLOW', 'explanation': []
        }

        response = client.post("/api/analyze", json={
            "email_string": "From: s@example.com\nSubject: T\n\nBody",
            "analyze_authentication": True
        })
        data = response.json()
        assert data["is_suspicious"] is False
        assert "DKIM_NONE" in data["spoofing_indicators"]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
