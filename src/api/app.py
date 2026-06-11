"""
FastAPI Application
Główna aplikacja REST API do wykrywania spoofingu
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import base64
import re
import logging
import threading
import uuid
from datetime import datetime

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from email_parser.parser import EmailParser
from email_parser.header_analyzer import HeaderAnalyzer
from email_parser.imap_client import IMAPClient
from authentication.spf_checker import SPFChecker
from authentication.dkim_checker import DKIMChecker
from authentication.dmarc_checker import DMARCChecker
from feature_extraction.extractor import FeatureExtractor
from ml_models.predict import EmailClassifier
from ml_models.model_manager import ModelManager
from utils.helpers import setup_logging, load_config, save_json, load_json
from utils.domain_utils import (
    get_organizational_domain,
    same_organizational_domain,
    extract_email_address,
)

logger = setup_logging()

config = load_config()

MAX_EMAIL_SIZE = 10 * 1024 * 1024

TRUSTED_SENDER_DOMAINS = {
    'google.com', 'accounts.google.com', 'gmail.com',
    'googlemail.com', 'youtube.com',
    'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
    'apple.com', 'icloud.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'github.com', 'amazon.com',
    'booksy.com', 'allegro.pl', 'olx.pl', 'inpost.pl',
    'mbank.pl', 'ing.pl', 'pkobp.pl', 'santander.pl',
    'spotify.com', 'netflix.com', 'paypal.com',
}


def compute_auth_alignment(email_data: Dict[str, Any],
                           authentication_results: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    """
    Ocena zgodności (alignment) SPF i DKIM z domeną pola From wg zasad DMARC.

    Pozwala odróżnić uwierzytelniony, legalny mailing (np. wysyłany przez
    dostawcę typu SendGrid z poddomeny ``em.spotify.com``) od faktycznego
    podszywania się pod cudzą domenę.
    """
    info = {
        'dkim_aligned': False,
        'spf_aligned': False,
        'dmarc_pass': False,
        'envelope_aligned': False,
    }

    if not authentication_results:
        return info

    from_email = email_data.get('from', {}).get('email', '')
    from_org = get_organizational_domain(from_email)
    if not from_org:
        return info

    dkim = authentication_results.get('dkim') or {}
    if dkim.get('valid'):
        for signature in dkim.get('signatures', []):
            signing_domain = (signature.get('d') or '').lower()
            if signing_domain and get_organizational_domain(signing_domain) == from_org:
                info['dkim_aligned'] = True
                break

    envelope_email = extract_email_address(email_data.get('return_path', '') or '') or from_email

    spf = authentication_results.get('spf') or {}
    if spf.get('valid') and get_organizational_domain(envelope_email) == from_org:
        info['spf_aligned'] = True

    info['envelope_aligned'] = same_organizational_domain(envelope_email, from_email)

    dmarc = authentication_results.get('dmarc') or {}
    if dmarc.get('valid') and (info['dkim_aligned'] or info['spf_aligned']):
        info['dmarc_pass'] = True

    # Fallback: gdy lokalne zapytania DNS zawiodą (temperror), zaufaj wynikom
    # uwierzytelniania dodanym przez serwer odbiorcy w nagłówku
    # Authentication-Results (jego topowe wystąpienie pochodzi od MTA odbiorcy).
    auth_header = email_data.get('authentication_results', '')
    if not auth_header:
        auth_header = email_data.get('headers', {}).get('Authentication-Results', '')
    if isinstance(auth_header, list):
        auth_header = ' '.join(auth_header)
    auth_lower = auth_header.lower() if auth_header else ''
    if 'dmarc=pass' in auth_lower:
        header_from_match = re.search(r'header\.from=([\w.\-]+)', auth_lower)
        header_from_org = (
            get_organizational_domain(header_from_match.group(1))
            if header_from_match else from_org
        )
        if header_from_org == from_org:
            info['dmarc_pass'] = True

    return info

app = FastAPI(
    title="Email Spoofing Detector API",
    description="REST API do wykrywania spoofingu i phishingu w wiadomościach e-mail",
    version="1.0.0"
)

_cors_origins = config.get('api', {}).get('cors_origins', [
    "http://localhost:3000",
    "http://localhost:5500",
    "http://localhost:8080",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8080",
    "null",
])
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_models_dir = str(Path(__file__).parent.parent.parent / "models")

email_parser = EmailParser()
header_analyzer = HeaderAnalyzer()
spf_checker = SPFChecker()
dkim_checker = DKIMChecker()
dmarc_checker = DMARCChecker()
feature_extractor = FeatureExtractor()
classifier = EmailClassifier(models_dir=_models_dir)
model_manager = ModelManager(models_dir=_models_dir)

_data_dir = Path(__file__).parent.parent.parent / "data"
_stats_file = _data_dir / "stats.json"
_alerts_file = _data_dir / "alerts.json"

def _load_persisted_stats() -> dict:
    try:
        if _stats_file.exists():
            return load_json(str(_stats_file))
    except Exception:
        pass
    return {'total_analyzed': 0, 'suspicious_detected': 0, 'safe_emails': 0, 'last_updated': None}

def _load_persisted_alerts() -> list:
    try:
        if _alerts_file.exists():
            return load_json(str(_alerts_file))
    except Exception:
        pass
    return []

alerts = _load_persisted_alerts()
statistics = _load_persisted_stats()

_state_lock = threading.Lock()

imap_monitor_active = False
imap_monitor_thread = None


class EmailAnalysisRequest(BaseModel):
    """Request do analizy e-maila"""
    raw_email: Optional[str] = Field(None, description="Surowa wiadomość zakodowana w base64")
    email_string: Optional[str] = Field(None, description="Wiadomość e-mail jako string")
    analyze_authentication: bool = Field(True, description="Czy sprawdzać SPF/DKIM/DMARC")
    
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "email_string": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nTest message",
                "analyze_authentication": True
            }]
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
    model_config = {"protected_namespaces": ()}
    
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
        if request.raw_email:
            if len(request.raw_email) > MAX_EMAIL_SIZE:
                raise HTTPException(status_code=413, detail="E-mail zbyt duży")
            try:
                raw_email_bytes = base64.b64decode(request.raw_email)
            except Exception:
                raise HTTPException(status_code=400, detail="Nieprawidłowe kodowanie base64")
            email_data = email_parser.parse_raw_email(raw_email_bytes)
        elif request.email_string:
            if len(request.email_string) > MAX_EMAIL_SIZE:
                raise HTTPException(status_code=413, detail="E-mail zbyt duży")
            email_data = email_parser.parse_email_string(request.email_string)
            raw_email_bytes = request.email_string.encode('utf-8', errors='replace')
        else:
            raise HTTPException(status_code=400, detail="Brak danych e-maila")

        header_analysis = header_analyzer.analyze(email_data)

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

        features = feature_extractor.extract_features(
            email_data,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            header_analysis=header_analysis
        )

        prediction = classifier.predict(features)

        alignment = compute_auth_alignment(email_data, authentication_results)

        if authentication_results:
            spf_ok = authentication_results['spf'].get('result') == 'pass'
            dkim_ok = authentication_results['dkim'].get('result') == 'pass'

            if not dkim_ok or not spf_ok:
                auth_header = email_data.get('authentication_results', '')
                if not auth_header:
                    auth_header = email_data.get('headers', {}).get('Authentication-Results', '')
                if isinstance(auth_header, list):
                    auth_header = ' '.join(auth_header)
                auth_lower = auth_header.lower() if auth_header else ''
                if not dkim_ok and 'dkim=pass' in auth_lower:
                    dkim_ok = True
                if not spf_ok and 'spf=pass' in auth_lower:
                    spf_ok = True

            sender_domain = email_data.get('from', {}).get('email', '').split('@')[-1].lower()
            from_org = get_organizational_domain(sender_domain)
            is_trusted = (
                sender_domain in TRUSTED_SENDER_DOMAINS
                or (from_org and from_org in TRUSTED_SENDER_DOMAINS)
            )

            factor = None
            if alignment['dmarc_pass']:
                factor = 0.25 if is_trusted else 0.5
            elif spf_ok and dkim_ok:
                factor = 0.4 if is_trusted else 0.6

            if factor is not None:
                prediction['confidence'] *= factor
                if prediction['confidence'] < 0.5:
                    prediction['is_suspicious'] = False
                    prediction['risk_level'] = 'LOW'
                    prediction['recommendation'] = 'ALLOW'
                elif prediction['confidence'] < 0.8:
                    prediction['risk_level'] = 'MEDIUM'
                    prediction['recommendation'] = 'FLAG'

        spoofing_indicators = []
        info_indicators = []
        
        if authentication_results:
            spf_result_str = authentication_results['spf'].get('result', 'none')
            if spf_result_str == 'fail' and not alignment['dmarc_pass']:
                spoofing_indicators.append("SPF_FAIL")
            elif spf_result_str == 'softfail' and not alignment['dmarc_pass']:
                spoofing_indicators.append("SPF_SOFTFAIL")
            elif spf_result_str == 'none' and not alignment['dmarc_pass']:
                info_indicators.append("SPF_NONE")
            
            dkim_data = authentication_results['dkim']
            if dkim_data.get('result') == 'fail' and not alignment['dmarc_pass']:
                spoofing_indicators.append("DKIM_FAIL")
            elif dkim_data.get('result') == 'none' and not alignment['dmarc_pass']:
                info_indicators.append("DKIM_NONE")
            
            if not authentication_results['dmarc'].get('valid'):
                if authentication_results['dmarc'].get('record'):
                    spoofing_indicators.append("DMARC_FAIL")
                else:
                    info_indicators.append("DMARC_NOT_CONFIGURED")
        
        if header_analysis.get('from_mismatch') and not (
            alignment['envelope_aligned'] or alignment['dmarc_pass']
        ):
            spoofing_indicators.append("FROM_RETURN_PATH_MISMATCH")
        
        if header_analysis.get('reply_to_mismatch') and not alignment['dmarc_pass']:
            spoofing_indicators.append("REPLY_TO_MISMATCH")

        all_indicators = spoofing_indicators + info_indicators

        if spoofing_indicators and not prediction['is_suspicious']:
            prediction['is_suspicious'] = True
            if prediction['risk_level'] == 'LOW':
                prediction['risk_level'] = 'MEDIUM'
            prediction['recommendation'] = _get_recommendation_from_risk(prediction['risk_level'])

        alert_id = None
        if prediction['is_suspicious']:
            alert_id = f"ALERT_{uuid.uuid4().hex[:12]}"

            background_tasks.add_task(
                save_alert,
                alert_id,
                email_data,
                prediction,
                authentication_results,
                all_indicators
            )

        update_statistics(prediction['is_suspicious'])

        response = EmailAnalysisResponse(
            is_suspicious=prediction['is_suspicious'],
            confidence=prediction['confidence'],
            risk_level=prediction['risk_level'],
            recommendation=prediction['recommendation'],
            spoofing_indicators=all_indicators,
            authentication=authentication_results,
            header_analysis=header_analysis,
            timestamp=datetime.now().isoformat(),
            alert_id=alert_id
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Błąd analizy e-maila: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Wewnętrzny błąd serwera podczas analizy")


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
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    risk_level: Optional[str] = None
):
    """
    Zwraca listę alertów
    """
    with _state_lock:
        filtered_alerts = list(alerts)
    
    if risk_level:
        filtered_alerts = [a for a in filtered_alerts if a.get('risk_level') == risk_level.upper()]
    
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
    with _state_lock:
        original_length = len(alerts)
        alerts = [a for a in alerts if a.get('alert_id') != alert_id]
        removed = len(alerts) < original_length
    
    if not removed:
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


@app.get("/api/evaluation-metrics")
async def get_evaluation_metrics():
    """Zwraca metryki ewaluacji modeli (precision, recall, F1-score) z ostatniego treningu"""
    eval_path = Path(_models_dir) / "evaluation_results.json"
    if not eval_path.exists():
        raise HTTPException(status_code=404, detail="Brak wyników ewaluacji - wytrenuj modele najpierw")
    
    try:
        return load_json(str(eval_path))
    except Exception:
        raise HTTPException(status_code=500, detail="Błąd odczytu wyników ewaluacji")


def save_alert(alert_id: str, 
              email_data: Dict[str, Any],
              prediction: Dict[str, Any],
              authentication: Optional[Dict[str, Any]],
              indicators: List[str]):
    """Zapisuje alert (wykonywane w tle, thread-safe)"""
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
    
    with _state_lock:
        alerts.append(alert)
        try:
            save_json(alerts, str(_alerts_file))
        except Exception as e:
            logger.warning(f"Nie udało się zapisać alertów: {e}")
    logger.info(f"Utworzono alert: {alert_id}")


def _get_recommendation_from_risk(risk_level: str) -> str:
    """Zwraca rekomendację na podstawie poziomu ryzyka"""
    mapping = {'HIGH': 'QUARANTINE', 'MEDIUM': 'FLAG', 'LOW': 'ALLOW'}
    return mapping.get(risk_level, 'FLAG')


def update_statistics(is_suspicious: bool):
    """Aktualizuje statystyki i zapisuje na dysk"""
    with _state_lock:
        statistics['total_analyzed'] += 1
        
        if is_suspicious:
            statistics['suspicious_detected'] += 1
        else:
            statistics['safe_emails'] += 1
        
        statistics['last_updated'] = datetime.now().isoformat()
        try:
            save_json(statistics, str(_stats_file))
        except Exception as e:
            logger.warning(f"Nie udało się zapisać statystyk: {e}")


def _process_imap_email(raw_email: bytes):
    """Callback do przetwarzania e-maili z monitorowania IMAP"""
    try:
        email_data = email_parser.parse_raw_email(raw_email)
        header_analysis = header_analyzer.analyze(email_data)
        
        spf_result = spf_checker.check_from_email_data(email_data)
        dkim_result = dkim_checker.check_from_email_data(email_data, raw_email)
        dmarc_result = dmarc_checker.check_from_email_data(email_data)
        
        features = feature_extractor.extract_features(
            email_data, spf_result=spf_result, dkim_result=dkim_result,
            dmarc_result=dmarc_result, header_analysis=header_analysis
        )
        
        prediction = classifier.predict(features)

        authentication_results = {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
        }
        alignment = compute_auth_alignment(email_data, authentication_results)

        spf_pass = spf_result and spf_result.get('result') == 'pass'
        dkim_pass = dkim_result and dkim_result.get('result') == 'pass'

        if not dkim_pass or not spf_pass:
            auth_header = email_data.get('authentication_results', '')
            if not auth_header:
                auth_header = email_data.get('headers', {}).get('Authentication-Results', '')
            if isinstance(auth_header, list):
                auth_header = ' '.join(auth_header)
            auth_lower = auth_header.lower() if auth_header else ''
            if not dkim_pass and 'dkim=pass' in auth_lower:
                dkim_pass = True
            if not spf_pass and 'spf=pass' in auth_lower:
                spf_pass = True

        sender_domain = email_data.get('from', {}).get('email', '').split('@')[-1].lower()
        from_org = get_organizational_domain(sender_domain)
        is_trusted = (
            sender_domain in TRUSTED_SENDER_DOMAINS
            or (from_org and from_org in TRUSTED_SENDER_DOMAINS)
        )

        factor = None
        if alignment['dmarc_pass']:
            factor = 0.25 if is_trusted else 0.5
        elif spf_pass and dkim_pass:
            factor = 0.4 if is_trusted else 0.6

        if factor is not None:
            prediction['confidence'] *= factor
            if prediction['confidence'] < 0.5:
                prediction['is_suspicious'] = False
                prediction['risk_level'] = 'LOW'
                prediction['recommendation'] = 'ALLOW'
            elif prediction['confidence'] < 0.8:
                prediction['risk_level'] = 'MEDIUM'
                prediction['recommendation'] = 'FLAG'

        update_statistics(prediction['is_suspicious'])

        if prediction['is_suspicious']:
            alert_id = f"IMAP_{uuid.uuid4().hex[:12]}"
            indicators = []
            if spf_result and spf_result.get('result') in ('fail', 'softfail'):
                indicators.append(f"SPF_{spf_result['result'].upper()}")
            if dkim_result and dkim_result.get('result') == 'fail':
                indicators.append("DKIM_FAIL")
            if header_analysis.get('from_mismatch') and not (
                alignment['envelope_aligned'] or alignment['dmarc_pass']
            ):
                indicators.append("FROM_RETURN_PATH_MISMATCH")
            save_alert(alert_id, email_data, prediction, None, indicators)
            
        logger.info(f"IMAP: przetworzono e-mail od {email_data.get('from', {}).get('email', '?')}, "
                     f"suspicious={prediction['is_suspicious']}")
    except Exception as e:
        logger.error(f"IMAP: błąd przetwarzania e-maila: {e}")


@app.post("/api/imap/start")
async def start_imap_monitoring(background_tasks: BackgroundTasks):
    """monitorowanie skrzynki IMAP"""
    global imap_monitor_active, imap_monitor_thread
    
    if imap_monitor_active:
        return {"status": "already_running", "message": "Monitorowanie IMAP jest już aktywne"}
    
    imap_config = config.get('imap', {})
    if not imap_config.get('server') or not imap_config.get('username'):
        raise HTTPException(status_code=400,
                            detail="Brak konfiguracji IMAP w config/config.yaml")
    
    def run_monitor():
        global imap_monitor_active
        imap_monitor_active = True
        interval = imap_config.get('check_interval', 60)
        try:
            client = IMAPClient(
                server=imap_config['server'],
                username=imap_config['username'],
                password=imap_config.get('password', ''),
                port=imap_config.get('port', 993),
                use_ssl=imap_config.get('ssl', True),
                folder=imap_config.get('folder', 'INBOX')
            )
            if not client.connect():
                logger.error("IMAP: nie udało się połączyć")
                return

            logger.info(f"IMAP: start monitorowania (interwał: {interval}s)")
            while imap_monitor_active:
                new_emails = client.fetch_new_emails(mark_as_seen=True)
                for raw_email in new_emails:
                    if not imap_monitor_active:
                        break
                    try:
                        _process_imap_email(raw_email)
                    except Exception as e:
                        logger.error(f"IMAP: błąd przetwarzania: {e}")
                for _ in range(interval):
                    if not imap_monitor_active:
                        break
                    import time
                    time.sleep(1)

            client.disconnect()
        except Exception as e:
            logger.error(f"Błąd monitorowania IMAP: {e}")
        finally:
            imap_monitor_active = False
            logger.info("IMAP: monitorowanie zatrzymane")
    
    imap_monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    imap_monitor_thread.start()
    
    return {"status": "started", "message": "Monitorowanie IMAP uruchomione"}


@app.post("/api/imap/stop")
async def stop_imap_monitoring():
    """Zatrzymuje monitorowanie IMAP"""
    global imap_monitor_active
    
    if not imap_monitor_active:
        return {"status": "not_running", "message": "Monitorowanie IMAP nie jest aktywne"}
    
    imap_monitor_active = False
    return {"status": "stopping", "message": "Zatrzymywanie monitorowania IMAP..."}


@app.get("/api/imap/status")
async def get_imap_status():
    """Zwraca status monitorowania IMAP"""
    return {
        "active": imap_monitor_active,
        "configured": bool(config.get('imap', {}).get('server'))
    }


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

