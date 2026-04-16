"""
Tests for API
Testy dla REST API
"""

import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

# Dodaj src do ścieżki
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


# Mock'uj komponenty przed importem app
with patch('src.api.app.EmailParser'), \
     patch('src.api.app.HeaderAnalyzer'), \
     patch('src.api.app.SPFChecker'), \
     patch('src.api.app.DKIMChecker'), \
     patch('src.api.app.DMARCChecker'), \
     patch('src.api.app.FeatureExtractor'), \
     patch('src.api.app.EmailClassifier'), \
     patch('src.api.app.ModelManager'):
    
    from api.app import app


@pytest.fixture
def client():
    """Fixture zwracający test client"""
    return TestClient(app)


@pytest.fixture
def sample_email_request():
    """Fixture z przykładowym requestem"""
    return {
        "email_string": """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a test email.
""",
        "analyze_authentication": True
    }


class TestAPIEndpoints:
    """Testy dla endpointów API"""
    
    def test_root_endpoint(self, client):
        """Test endpointu głównego"""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
    
    def test_health_check(self, client):
        """Test health check"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "models_loaded" in data
    
    def test_get_stats(self, client):
        """Test pobierania statystyk"""
        response = client.get("/api/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_analyzed" in data
        assert "suspicious_detected" in data
        assert "safe_emails" in data
        assert "detection_rate" in data
    
    def test_get_alerts(self, client):
        """Test pobierania alertów"""
        response = client.get("/api/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "alerts" in data
        assert isinstance(data["alerts"], list)
    
    def test_get_alerts_with_filter(self, client):
        """Test pobierania alertów z filtrem"""
        response = client.get("/api/alerts?risk_level=HIGH")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
    
    def test_get_models_info(self, client):
        """Test pobierania informacji o modelach"""
        response = client.get("/api/models")
        
        assert response.status_code == 200
        data = response.json()
        assert "models" in data
        assert "loaded" in data


class TestAnalyzeEndpoint:
    """Testy dla endpointu analizy e-maili"""
    
    @patch('api.app.email_parser')
    @patch('api.app.classifier')
    def test_analyze_email_success(self, mock_classifier, mock_parser, 
                                   client, sample_email_request):
        """Test pomyślnej analizy e-maila"""
        # Mock parser
        mock_parser.parse_email_string.return_value = {
            'from': {'email': 'sender@example.com'},
            'to': [{'email': 'recipient@example.com'}],
            'subject': 'Test',
            'body': {'plain': 'Test body', 'html': ''}
        }
        
        # Mock classifier
        mock_classifier.predict.return_value = {
            'is_suspicious': False,
            'confidence': 0.2,
            'risk_level': 'LOW',
            'recommendation': 'ALLOW',
            'explanation': []
        }
        
        response = client.post("/api/analyze", json=sample_email_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "is_suspicious" in data
        assert "confidence" in data
        assert "risk_level" in data
        assert "recommendation" in data
    
    def test_analyze_email_missing_data(self, client):
        """Test analizy bez danych"""
        response = client.post("/api/analyze", json={
            "analyze_authentication": True
        })
        
        assert response.status_code == 400
    
    def test_analyze_email_invalid_format(self, client):
        """Test analizy z nieprawidłowym formatem"""
        response = client.post("/api/analyze", json={
            "email_string": "invalid format",
            "analyze_authentication": False
        })
        
        # Może zwrócić 500 lub przetworzyć z błędami
        assert response.status_code in [200, 400, 500]


class TestAlertsManagement:
    """Testy zarządzania alertami"""
    
    def test_get_nonexistent_alert(self, client):
        """Test pobierania nieistniejącego alertu"""
        response = client.get("/api/alerts/NONEXISTENT_ID")
        
        assert response.status_code == 404
    
    def test_delete_nonexistent_alert(self, client):
        """Test usuwania nieistniejącego alertu"""
        response = client.delete("/api/alerts/NONEXISTENT_ID")
        
        assert response.status_code == 404


class TestFeatureImportance:
    """Testy endpointu feature importance"""
    
    @patch('api.app.classifier')
    def test_get_feature_importance(self, mock_classifier, client):
        """Test pobierania ważności cech"""
        import pandas as pd
        
        # Mock feature importance
        mock_classifier.get_feature_importance.return_value = pd.DataFrame({
            'feature': ['spf_pass', 'dkim_valid'],
            'importance': [0.5, 0.3]
        })
        
        response = client.get("/api/feature-importance")
        
        assert response.status_code == 200
        data = response.json()
        assert "features" in data
    
    @patch('api.app.classifier')
    def test_get_feature_importance_no_model(self, mock_classifier, client):
        """Test gdy model nie jest załadowany"""
        mock_classifier.get_feature_importance.return_value = None
        
        response = client.get("/api/feature-importance")
        
        assert response.status_code == 404


class TestAPIValidation:
    """Testy walidacji requestów"""
    
    def test_invalid_json(self, client):
        """Test nieprawidłowego JSON"""
        response = client.post(
            "/api/analyze",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_missing_required_fields(self, client):
        """Test brakujących wymaganych pól"""
        response = client.post("/api/analyze", json={})
        
        assert response.status_code == 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

