"""
Tests for ModelManager
Testy zarządzania metadanymi, wersjami i eksportem modeli
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from ml_models.model_manager import ModelManager


@pytest.fixture
def manager(tmp_path):
    return ModelManager(models_dir=str(tmp_path / "models"))


class TestInitialization:
    """Testy inicjalizacji i wczytywania metadanych"""

    def test_creates_models_dir(self, tmp_path):
        models_dir = tmp_path / "models"
        ModelManager(models_dir=str(models_dir))
        assert models_dir.exists()

    def test_empty_metadata_on_fresh_dir(self, manager):
        assert manager.list_models() == {}

    def test_load_corrupt_metadata_returns_empty(self, tmp_path):
        """Uszkodzony metadata.json nie powinien crashować — zwraca pusty słownik"""
        d = tmp_path / "models"
        d.mkdir()
        (d / "metadata.json").write_text("{ this is not valid json")
        manager = ModelManager(models_dir=str(d))
        assert manager.list_models() == {}


class TestRegisterModel:
    """Testy rejestrowania modeli"""

    def test_register_returns_version_and_sets_current(self, manager):
        version = manager.register_model('rf', 'random_forest', {'f1_score': 0.9})
        assert version is not None
        assert manager.get_current_version('rf') == version

    def test_register_explicit_version(self, manager):
        version = manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')
        assert version == 'v1'
        info = manager.get_model_info('rf')
        assert info['type'] == 'random_forest'
        assert 'v1' in info['versions']
        assert info['versions']['v1']['metrics']['f1_score'] == 0.9

    def test_register_persists_to_disk(self, tmp_path):
        """Nowa instancja managera wczytuje metadane zapisane przez poprzednią"""
        d = str(tmp_path / "models")
        ModelManager(models_dir=d).register_model(
            'rf', 'random_forest', {'f1_score': 0.9}, version='v1'
        )
        reloaded = ModelManager(models_dir=d)
        assert reloaded.get_current_version('rf') == 'v1'


class TestVersionManagement:
    """Testy zmiany aktualnej wersji"""

    def test_set_current_version_valid(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.8}, version='v1')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v2')
        manager.set_current_version('rf', 'v1')
        assert manager.get_current_version('rf') == 'v1'

    def test_set_current_version_invalid_ignored(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.8}, version='v1')
        manager.set_current_version('rf', 'nonexistent')
        assert manager.get_current_version('rf') == 'v1'

    def test_get_current_version_unknown_model(self, manager):
        assert manager.get_current_version('ghost') is None


class TestCompareVersions:
    """Testy porównywania wersji"""

    def test_compare_computes_differences(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.80}, version='v1')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.90}, version='v2')
        comparison = manager.compare_versions('rf', 'v1', 'v2')
        assert comparison['differences']['f1_score']['absolute'] == pytest.approx(0.10)

    def test_compare_unknown_model(self, manager):
        assert manager.compare_versions('ghost', 'v1', 'v2') == {}

    def test_compare_unknown_version(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')
        assert manager.compare_versions('rf', 'v1', 'v9') == {}


class TestDeleteVersion:
    """Testy usuwania wersji"""

    def test_delete_marks_status(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')
        manager.delete_version('rf', 'v1')
        info = manager.get_model_info('rf')
        assert info['versions']['v1']['status'] == 'deleted'

    def test_delete_current_clears_current(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')
        manager.delete_version('rf', 'v1')
        assert manager.get_current_version('rf') is None


class TestBestVersion:
    """Testy wyboru najlepszej wersji"""

    def test_best_by_f1(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.80}, version='v1')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.95}, version='v2')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.88}, version='v3')
        assert manager.get_best_version('rf', metric='f1_score') == 'v2'

    def test_best_ignores_deleted(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.99}, version='v1')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.80}, version='v2')
        manager.delete_version('rf', 'v1')
        assert manager.get_best_version('rf', metric='f1_score') == 'v2'

    def test_best_unknown_model(self, manager):
        assert manager.get_best_version('ghost') is None


class TestModelStats:
    """Testy statystyk modeli"""

    def test_stats_counts(self, manager):
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.92}, version='v2')
        manager.register_model('if', 'isolation_forest', {'f1_score': 0.7}, version='v1')
        manager.delete_version('rf', 'v1')

        stats = manager.get_model_stats()
        assert stats['total_models'] == 2
        assert stats['models']['rf']['total_versions'] == 2
        assert stats['models']['rf']['active_versions'] == 1
        assert stats['models']['if']['active_versions'] == 1


class TestExportModel:
    """Testy eksportu modelu"""

    def test_export_copies_joblib_and_metadata(self, manager, tmp_path):
        (manager.models_dir / "random_forest_classifier.joblib").write_bytes(b'dummy-model')
        manager.register_model('rf', 'random_forest', {'f1_score': 0.9}, version='v1')

        export_dir = tmp_path / "export"
        manager.export_model('rf', 'v1', str(export_dir))

        assert (export_dir / "random_forest_classifier.joblib").exists()
        assert (export_dir / "metadata.json").exists()

    def test_export_unknown_model_noop(self, manager, tmp_path):
        export_dir = tmp_path / "export_ghost"
        manager.export_model('ghost', 'v1', str(export_dir))
        assert not (export_dir / "metadata.json").exists()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
