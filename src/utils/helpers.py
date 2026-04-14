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
    Konfiguruje system logowania
    
    Args:
        log_level: Poziom logowania (DEBUG, INFO, WARNING, ERROR)
        log_file: Ścieżka do pliku logów (opcjonalne)
        log_format: Format logów (json lub text)
        
    Returns:
        Skonfigurowany logger
    """
    # Konwertuj poziom logowania
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Konfiguracja formattera
    if log_format == "json":
        from pythonjsonlogger import jsonlogger
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Konfiguracja handlera
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)
    
    # File handler (jeśli określono)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Konfiguracja root loggera
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
    
    Args:
        config_path: Ścieżka do pliku konfiguracyjnego
        
    Returns:
        Słownik z konfiguracją
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
    """
    Zapisuje dane do pliku JSON
    
    Args:
        data: Dane do zapisania
        file_path: Ścieżka do pliku
        indent: Wcięcie JSON
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False, default=str)


def load_json(file_path: str) -> Any:
    """
    Ładuje dane z pliku JSON
    
    Args:
        file_path: Ścieżka do pliku
        
    Returns:
        Załadowane dane
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def calculate_metrics(y_true, y_pred) -> Dict[str, float]:
    """
    Oblicza metryki klasyfikacji
    
    Args:
        y_true: Prawdziwe etykiety
        y_pred: Predykcje
        
    Returns:
        Słownik z metrykami
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
    
    # Macierz pomyłek
    cm = confusion_matrix(y_true, y_pred)
    metrics['true_negatives'] = int(cm[0][0])
    metrics['false_positives'] = int(cm[0][1])
    metrics['false_negatives'] = int(cm[1][0])
    metrics['true_positives'] = int(cm[1][1])
    
    # ROC AUC (jeśli są dostępne prawdopodobieństwa)
    try:
        metrics['roc_auc'] = roc_auc_score(y_true, y_pred)
    except:
        pass
    
    return metrics


def get_timestamp() -> str:
    """Zwraca aktualny timestamp w formacie ISO"""
    return datetime.now().isoformat()


def create_directory(path: str):
    """Tworzy katalog jeśli nie istnieje"""
    Path(path).mkdir(parents=True, exist_ok=True)


def file_exists(path: str) -> bool:
    """Sprawdza czy plik istnieje"""
    return Path(path).exists()


def sanitize_filename(filename: str) -> str:
    """
    Czyści nazwę pliku z nieprawidłowych znaków
    
    Args:
        filename: Nazwa pliku do wyczyszczenia
        
    Returns:
        Wyczyszczona nazwa pliku
    """
    import re
    # Usuń znaki specjalne
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    # Ogranicz długość
    if len(filename) > 255:
        filename = filename[:255]
    return filename


def format_file_size(size_bytes: int) -> str:
    """
    Formatuje rozmiar pliku do czytelnej formy
    
    Args:
        size_bytes: Rozmiar w bajtach
        
    Returns:
        Sformatowany rozmiar (np. "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def extract_domain(email: str) -> Optional[str]:
    """
    Ekstrahuje domenę z adresu e-mail
    
    Args:
        email: Adres e-mail
        
    Returns:
        Domena lub None
    """
    if '@' in email:
        return email.split('@')[1].lower()
    return None

