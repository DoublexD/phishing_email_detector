"""
Model Manager
Zarządzanie modelami - ładowanie, zapisywanie, wersjonowanie
"""

import joblib
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ModelManager:
    """Klasa do zarządzania modelami ML"""
    
    def __init__(self, models_dir: str = "models"):
        """
        Inicjalizacja managera modeli
        
        Args:
            models_dir: Katalog z modelami
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.models_dir / "metadata.json"
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Ładuje metadane modeli"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Błąd ładowania metadanych: {e}")
                return {}
        return {}
    
    def _save_metadata(self):
        """Zapisuje metadane modeli"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Błąd zapisywania metadanych: {e}")
    
    def register_model(self,
                      model_name: str,
                      model_type: str,
                      metrics: Dict[str, Any],
                      version: Optional[str] = None) -> str:
        """
        Rejestruje nowy model w metadanych
        
        Args:
            model_name: Nazwa modelu
            model_type: Typ modelu (random_forest, isolation_forest)
            metrics: Metryki wydajności
            version: Wersja modelu (jeśli None, zostanie wygenerowana)
            
        Returns:
            Wersja modelu
        """
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if model_name not in self.metadata:
            self.metadata[model_name] = {
                'type': model_type,
                'versions': {},
                'current_version': None
            }
        
        self.metadata[model_name]['versions'][version] = {
            'created_at': datetime.now().isoformat(),
            'metrics': metrics,
            'status': 'active'
        }
        
        # Ustaw jako aktualną wersję
        self.metadata[model_name]['current_version'] = version
        
        self._save_metadata()
        logger.info(f"Zarejestrowano model {model_name} wersja {version}")
        
        return version
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """
        Pobiera informacje o modelu
        
        Args:
            model_name: Nazwa modelu
            
        Returns:
            Informacje o modelu
        """
        return self.metadata.get(model_name)
    
    def get_current_version(self, model_name: str) -> Optional[str]:
        """
        Pobiera aktualną wersję modelu
        
        Args:
            model_name: Nazwa modelu
            
        Returns:
            Wersja modelu
        """
        model_info = self.metadata.get(model_name)
        if model_info:
            return model_info.get('current_version')
        return None
    
    def set_current_version(self, model_name: str, version: str):
        """
        Ustawia aktualną wersję modelu
        
        Args:
            model_name: Nazwa modelu
            version: Wersja do ustawienia
        """
        if model_name in self.metadata:
            if version in self.metadata[model_name]['versions']:
                self.metadata[model_name]['current_version'] = version
                self._save_metadata()
                logger.info(f"Ustawiono {model_name} na wersję {version}")
            else:
                logger.error(f"Wersja {version} nie istnieje dla modelu {model_name}")
        else:
            logger.error(f"Model {model_name} nie istnieje")
    
    def list_models(self) -> Dict[str, Any]:
        """
        Listuje wszystkie modele
        
        Returns:
            Słownik z modelami
        """
        return self.metadata
    
    def compare_versions(self, 
                        model_name: str,
                        version1: str,
                        version2: str) -> Dict[str, Any]:
        """
        Porównuje dwie wersje modelu
        
        Args:
            model_name: Nazwa modelu
            version1: Pierwsza wersja
            version2: Druga wersja
            
        Returns:
            Porównanie metryk
        """
        if model_name not in self.metadata:
            return {}
        
        versions = self.metadata[model_name]['versions']
        
        if version1 not in versions or version2 not in versions:
            return {}
        
        v1_metrics = versions[version1].get('metrics', {})
        v2_metrics = versions[version2].get('metrics', {})
        
        comparison = {
            'version1': {
                'version': version1,
                'metrics': v1_metrics
            },
            'version2': {
                'version': version2,
                'metrics': v2_metrics
            },
            'differences': {}
        }
        
        # Oblicz różnice w metrykach
        common_metrics = set(v1_metrics.keys()) & set(v2_metrics.keys())
        for metric in common_metrics:
            if isinstance(v1_metrics[metric], (int, float)) and isinstance(v2_metrics[metric], (int, float)):
                diff = v2_metrics[metric] - v1_metrics[metric]
                comparison['differences'][metric] = {
                    'absolute': diff,
                    'relative': (diff / v1_metrics[metric] * 100) if v1_metrics[metric] != 0 else None
                }
        
        return comparison
    
    def delete_version(self, model_name: str, version: str):
        """
        Usuwa wersję modelu
        
        Args:
            model_name: Nazwa modelu
            version: Wersja do usunięcia
        """
        if model_name in self.metadata:
            if version in self.metadata[model_name]['versions']:
                # Oznacz jako nieaktywną zamiast usuwać
                self.metadata[model_name]['versions'][version]['status'] = 'deleted'
                self._save_metadata()
                logger.info(f"Usunięto wersję {version} modelu {model_name}")
                
                # Jeśli to była aktualna wersja, ustaw na None
                if self.metadata[model_name]['current_version'] == version:
                    self.metadata[model_name]['current_version'] = None
                    logger.warning(f"Usunięto aktualną wersję modelu {model_name}")
    
    def get_best_version(self, 
                        model_name: str,
                        metric: str = 'f1_score') -> Optional[str]:
        """
        Znajduje najlepszą wersję modelu według podanej metryki
        
        Args:
            model_name: Nazwa modelu
            metric: Metryka do porównania
            
        Returns:
            Najlepsza wersja
        """
        if model_name not in self.metadata:
            return None
        
        versions = self.metadata[model_name]['versions']
        best_version = None
        best_score = -float('inf')
        
        for version, data in versions.items():
            if data.get('status') != 'active':
                continue
            
            metrics = data.get('metrics', {})
            if metric in metrics:
                score = metrics[metric]
                if isinstance(score, (int, float)) and score > best_score:
                    best_score = score
                    best_version = version
        
        return best_version
    
    def export_model(self, 
                    model_name: str,
                    version: str,
                    export_path: str):
        """
        Eksportuje model do innej lokalizacji
        
        Args:
            model_name: Nazwa modelu
            version: Wersja modelu
            export_path: Ścieżka docelowa
        """
        import shutil
        
        if model_name not in self.metadata:
            logger.error(f"Model {model_name} nie istnieje")
            return
        
        if version not in self.metadata[model_name].get('versions', {}):
            logger.error(f"Wersja {version} nie istnieje dla {model_name}")
            return
        
        export_dir = Path(export_path)
        export_dir.mkdir(parents=True, exist_ok=True)
        
        model_files = list(self.models_dir.glob("*.joblib"))
        for model_file in model_files:
            dest = export_dir / model_file.name
            shutil.copy2(model_file, dest)
            logger.info(f"Wyeksportowano: {model_file.name} -> {dest}")
        
        metadata_dest = export_dir / "metadata.json"
        import json
        with open(metadata_dest, 'w') as f:
            json.dump({model_name: self.metadata[model_name]}, f, indent=2, default=str)
        
        logger.info(f"Eksport modelu {model_name} v{version} zakończony: {export_path}")
    
    def get_model_stats(self) -> Dict[str, Any]:
        """
        Zwraca statystyki wszystkich modeli
        
        Returns:
            Statystyki modeli
        """
        stats = {
            'total_models': len(self.metadata),
            'models': {}
        }
        
        for model_name, model_info in self.metadata.items():
            active_versions = sum(
                1 for v in model_info['versions'].values() 
                if v.get('status') == 'active'
            )
            
            stats['models'][model_name] = {
                'type': model_info.get('type'),
                'total_versions': len(model_info['versions']),
                'active_versions': active_versions,
                'current_version': model_info.get('current_version')
            }
        
        return stats

