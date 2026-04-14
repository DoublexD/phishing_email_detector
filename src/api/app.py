"""
FastAPI Application
Główna aplikacja REST API do wykrywania spoofingu
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import base64
import logging
from datetime import datetime

# Importy lokalne
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from email_parser.parser import EmailParser
from email_parser.header_analyzer import HeaderAnalyzer
from authentication.spf_checker import SPFChecker
from authentication.dkim_checker import DKIMChecker
from authentication.dmarc_checker import DMARCChecker
from feature_extraction.extractor import FeatureExtractor
from ml_models.predict import EmailClassifier
from ml_models.model_manager import ModelManager
from utils.helpers import setup_logging, load_config

# Konfiguracja logowania
logger = setup_logging()

# Ładowanie konfiguracji
config = load_config()

# Inicjalizacja FastAPI
app = FastAPI(
    title="Email Spoofing Detector API",
    description="REST API do wykrywania spoofingu i phishingu w wiadomościach e-mail",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # W produkcji należy ograniczyć
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ścieżka do modeli — zawsze względem lokalizacji tego pliku (src/api/app.py → ../../models)
_models_dir = str(Path(__file__).parent.parent.parent / "models")

# Inicjalizacja komponentów
email_parser = EmailParser()
header_analyzer = HeaderAnalyzer()
spf_checker = SPFChecker()
dkim_checker = DKIMChecker()
dmarc_checker = DMARCChecker()
feature_extractor = FeatureExtractor()
classifier = EmailClassifier(models_dir=_models_dir)
model_manager = ModelManager(models_dir=_models_dir)

# Przechowywanie alertów (w produkcji użyj bazy danych)
alerts = []
statistics = {
    'total_analyzed': 0,
    'suspicious_detected': 0,
    'safe_emails': 0,
    'last_updated': None
}


# Modele Pydantic
class EmailAnalysisRequest(BaseModel):
    """Request do analizy e-maila"""
    raw_email: Optional[str] = Field(None, description="Surowa wiadomość zakodowana w base64")
    email_string: Optional[str] = Field(None, description="Wiadomość e-mail jako string")
    analyze_authentication: bool = Field(True, description="Czy sprawdzać SPF/DKIM/DMARC")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email_string": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nTest message",
                "analyze_authentication": True
            }
        }


class EmailAnalysisResponse(BaseModel):
    """Odpowiedź z analizy e-maila"""
    is_suspicious: bool
    confidence: float
    risk_level: str
    recommendation: str
    spoofing_indicators: List[str]
    authentication: Optional[Dict[str, Any]] = None
    header_analysis: Optional[Dict[str, Any]] = None
    timestamp: str
    alert_id: Optional[str] = None


class StatsResponse(BaseModel):
    """Statystyki systemu"""
    total_analyzed: int
    suspicious_detected: int
    safe_emails: int
    detection_rate: float
    last_updated: Optional[str]
    model_info: Dict[str, Any]


class HealthResponse(BaseModel):
    """Status zdrowia API"""
    status: str
    version: str
    models_loaded: Dict[str, bool]
    timestamp: str


# Endpointy
@app.get("/", response_model=Dict[str, str])
async def root():
    """Endpoint główny"""
    return {
        "message": "Email Spoofing Detector API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Sprawdzenie stanu API"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        models_loaded={
            "random_forest": classifier.random_forest is not None,
            "isolation_forest": classifier.isolation_forest is not None,
            "scaler": classifier.scaler is not None
        },
        timestamp=datetime.now().isoformat()
    )


@app.post("/api/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analizuje wiadomość e-mail pod kątem spoofingu
    """
    try:
        # Parsuj e-mail
        if request.raw_email:
            raw_email_bytes = base64.b64decode(request.raw_email)
            email_data = email_parser.parse_raw_email(raw_email_bytes)
        elif request.email_string:
            email_data = email_parser.parse_email_string(request.email_string)
            raw_email_bytes = request.email_string.encode('utf-8')
        else:
            raise HTTPException(status_code=400, detail="Brak danych e-maila")
        
        # Analiza nagłówków
        header_analysis = header_analyzer.analyze(email_data)
        
        # Autentykacja (jeśli włączona)
        authentication_results = None
        if request.analyze_authentication:
            spf_result = spf_checker.check_from_email_data(email_data)
            dkim_result = dkim_checker.check_from_email_data(email_data, raw_email_bytes)
            dmarc_result = dmarc_checker.check_from_email_data(email_data)
            
            authentication_results = {
                'spf': spf_result,
                'dkim': dkim_result,
                'dmarc': dmarc_result
            }
        else:
            spf_result = None
            dkim_result = None
            dmarc_result = None
        
        # Ekstrakcja cech
        features = feature_extractor.extract_features(
            email_data,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            header_analysis=header_analysis
        )
        
        # Klasyfikacja
        prediction = classifier.predict(features)
        
        # Zbierz wskaźniki spoofingu
        spoofing_indicators = []
        
        if authentication_results:
            if authentication_results['spf'].get('result') in ['fail', 'softfail']:
                spoofing_indicators.append(f"SPF_{authentication_results['spf']['result'].upper()}")
            if not authentication_results['dkim'].get('valid'):
                spoofing_indicators.append("DKIM_INVALID")
            if not authentication_results['dmarc'].get('valid'):
                spoofing_indicators.append("DMARC_NOT_CONFIGURED")
        
        if header_analysis.get('from_mismatch'):
            spoofing_indicators.append("FROM_RETURN_PATH_MISMATCH")
        
        if header_analysis.get('reply_to_mismatch'):
            spoofing_indicators.append("REPLY_TO_MISMATCH")

        # Reguły nadrzędne: wskaźniki spoofingu z nagłówków wymuszają podejrzany status
        if spoofing_indicators and not prediction['is_suspicious']:
            prediction['is_suspicious'] = True
            if prediction['risk_level'] == 'LOW':
                prediction['risk_level'] = 'MEDIUM'
            prediction['recommendation'] = _get_recommendation_from_risk(prediction['risk_level'])

        # Generuj alert ID jeśli podejrzane
        alert_id = None
        if prediction['is_suspicious']:
            alert_id = f"ALERT_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(alerts)}"
            
            # Dodaj do alertów (w tle)
            background_tasks.add_task(
                save_alert,
                alert_id,
                email_data,
                prediction,
                authentication_results,
                spoofing_indicators
            )
        
        # Aktualizuj statystyki
        update_statistics(prediction['is_suspicious'])
        
        # Przygotuj odpowiedź
        response = EmailAnalysisResponse(
            is_suspicious=prediction['is_suspicious'],
            confidence=prediction['confidence'],
            risk_level=prediction['risk_level'],
            recommendation=prediction['recommendation'],
            spoofing_indicators=spoofing_indicators,
            authentication=authentication_results,
            header_analysis=header_analysis,
            timestamp=datetime.now().isoformat(),
            alert_id=alert_id
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Błąd analizy e-maila: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Błąd analizy: {str(e)}")


@app.get("/api/stats", response_model=StatsResponse)
async def get_statistics():
    """Zwraca statystyki systemu"""
    detection_rate = 0.0
    if statistics['total_analyzed'] > 0:
        detection_rate = statistics['suspicious_detected'] / statistics['total_analyzed']
    
    model_stats = model_manager.get_model_stats()
    
    return StatsResponse(
        total_analyzed=statistics['total_analyzed'],
        suspicious_detected=statistics['suspicious_detected'],
        safe_emails=statistics['safe_emails'],
        detection_rate=detection_rate,
        last_updated=statistics['last_updated'],
        model_info=model_stats
    )


@app.get("/api/alerts")
async def get_alerts(limit: int = 50, risk_level: Optional[str] = None):
    """
    Zwraca listę alertów
    
    Args:
        limit: Maksymalna liczba alertów
        risk_level: Filtruj według poziomu ryzyka (HIGH, MEDIUM, LOW)
    """
    filtered_alerts = alerts
    
    if risk_level:
        filtered_alerts = [a for a in alerts if a.get('risk_level') == risk_level.upper()]
    
    return {
        "total": len(filtered_alerts),
        "alerts": filtered_alerts[-limit:]
    }


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Zwraca szczegóły konkretnego alertu"""
    for alert in alerts:
        if alert.get('alert_id') == alert_id:
            return alert
    
    raise HTTPException(status_code=404, detail="Alert nie znaleziony")


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    """Usuwa alert"""
    global alerts
    original_length = len(alerts)
    alerts = [a for a in alerts if a.get('alert_id') != alert_id]
    
    if len(alerts) == original_length:
        raise HTTPException(status_code=404, detail="Alert nie znaleziony")
    
    return {"message": "Alert usunięty", "alert_id": alert_id}


@app.get("/api/models")
async def get_models_info():
    """Zwraca informacje o załadowanych modelach"""
    return {
        "models": model_manager.list_models(),
        "loaded": {
            "random_forest": classifier.random_forest is not None,
            "isolation_forest": classifier.isolation_forest is not None,
        },
        "feature_count": len(classifier.feature_names) if classifier.feature_names else 0
    }


@app.get("/api/feature-importance")
async def get_feature_importance(top_n: int = 20):
    """Zwraca najważniejsze cechy z modelu"""
    importance = classifier.get_feature_importance(top_n=top_n)
    
    if importance is None:
        raise HTTPException(status_code=404, detail="Model nie załadowany lub brak danych")
    
    return {
        "features": importance.to_dict('records')
    }


# Funkcje pomocnicze
def save_alert(alert_id: str, 
              email_data: Dict[str, Any],
              prediction: Dict[str, Any],
              authentication: Optional[Dict[str, Any]],
              indicators: List[str]):
    """Zapisuje alert (wykonywane w tle)"""
    alert = {
        'alert_id': alert_id,
        'timestamp': datetime.now().isoformat(),
        'risk_level': prediction['risk_level'],
        'confidence': prediction['confidence'],
        'from': email_data.get('from'),
        'to': email_data.get('to'),
        'subject': email_data.get('subject'),
        'spoofing_indicators': indicators,
        'recommendation': prediction['recommendation']
    }
    
    alerts.append(alert)
    logger.info(f"Utworzono alert: {alert_id}")


def _get_recommendation_from_risk(risk_level: str) -> str:
    """Zwraca rekomendację na podstawie poziomu ryzyka"""
    mapping = {'HIGH': 'QUARANTINE', 'MEDIUM': 'FLAG', 'LOW': 'ALLOW'}
    return mapping.get(risk_level, 'FLAG')


def update_statistics(is_suspicious: bool):
    """Aktualizuje statystyki"""
    statistics['total_analyzed'] += 1
    
    if is_suspicious:
        statistics['suspicious_detected'] += 1
    else:
        statistics['safe_emails'] += 1
    
    statistics['last_updated'] = datetime.now().isoformat()


# Uruchomienie aplikacji
def main():
    """Główna funkcja uruchamiająca API"""
    import uvicorn
    
    host = config.get('api', {}).get('host', '0.0.0.0')
    port = config.get('api', {}).get('port', 8000)
    reload = config.get('api', {}).get('reload', False)
    
    logger.info(f"Uruchamianie API na {host}:{port}")
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()

