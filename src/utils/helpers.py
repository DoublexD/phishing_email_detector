"""
Helper Functions
Funkcje pomocnicze używane w całym projekcie
"""

import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import sys


def setup_logging(log_level: str = "INFO",
                 log_file: Optional[str] = None,
                 log_format: str = "json") -> logging.Logger:
    """
    Konfiguruje logowanie aplikacji: ustawia poziom, format oraz opcjonalny zapis do pliku.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    if log_format == "json":
        from pythonjsonlogger import jsonlogger
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    handlers = []

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(
        level=numeric_level,
        handlers=handlers
    )
    
    logger = logging.getLogger('email_spoofing_detector')
    logger.setLevel(numeric_level)
    
    return logger


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Ładuje plik konfiguracyjny YAML
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logging.warning(f"Plik konfiguracyjny nie znaleziony: {config_path}")
        return {}
    except Exception as e:
        logging.error(f"Błąd ładowania konfiguracji: {e}")
        return {}


def save_json(data: Any, file_path: str, indent: int = 2):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False, default=str)


def load_json(file_path: str) -> Any:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def calculate_metrics(y_true, y_pred) -> Dict[str, float]:
    """
    Oblicza metryki klasyfikacji
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, 
        f1_score, confusion_matrix, roc_auc_score
    )
    
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, average='binary'),
        'recall': recall_score(y_true, y_pred, average='binary'),
        'f1_score': f1_score(y_true, y_pred, average='binary'),
    }

    cm = confusion_matrix(y_true, y_pred)
    metrics['true_negatives'] = int(cm[0][0])
    metrics['false_positives'] = int(cm[0][1])
    metrics['false_negatives'] = int(cm[1][0])
    metrics['true_positives'] = int(cm[1][1])

    try:
        metrics['roc_auc'] = roc_auc_score(y_true, y_pred)
    except (ValueError, TypeError):
        pass
    
    return metrics


def get_timestamp() -> str:
    return datetime.now().isoformat()


def create_directory(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def file_exists(path: str) -> bool:
    return Path(path).exists()


def sanitize_filename(filename: str) -> str:
    """
    Czyści nazwę pliku z nieprawidłowych znaków
    """
    import re
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    if len(filename) > 255:
        filename = filename[:255]
    return filename


def format_file_size(size_bytes: int) -> str:
    """
    Formatuje rozmiar pliku do czytelnej formy
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def extract_domain(email: str) -> Optional[str]:
    """
    Ekstrahuje domenę z adresu e-mail
    """
    if '@' in email:
        return email.split('@')[1].lower()
    return None

