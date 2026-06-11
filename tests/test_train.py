"""
Tests for Model Training
Testy trenera — w tym naprawiony stratify crash i ostrzeżenie o data leakage
"""

import pytest
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from ml_models.train import ModelTrainer


@pytest.fixture
def trainer(tmp_path):
    return ModelTrainer(models_dir=str(tmp_path))


@pytest.fixture
def balanced_dataset():
    """Zrównoważony zbiór danych z 2 klasami"""
    np.random.seed(42)
    n = 100
    X = pd.DataFrame({
        'feature1': np.random.randn(n),
        'feature2': np.random.randn(n),
        'feature3': np.random.randn(n),
    })
    y = pd.Series([0] * 50 + [1] * 50)
    return X, y


@pytest.fixture
def single_class_dataset():
    """Zbiór danych z tylko jedną klasą"""
    np.random.seed(42)
    n = 50
    X = pd.DataFrame({
        'feature1': np.random.randn(n),
        'feature2': np.random.randn(n),
        'feature3': np.random.randn(n),
    })
    y = pd.Series([0] * n)
    return X, y


@pytest.fixture
def small_dataset():
    """Minimalny zbiór z 2 klasami"""
    X = pd.DataFrame({
        'feature1': [0.1, 0.2, 0.9, 0.8, 0.15, 0.85],
        'feature2': [0.2, 0.3, 0.7, 0.6, 0.25, 0.75],
    })
    y = pd.Series([0, 0, 1, 1, 0, 1])
    return X, y


class TestPrepareData:
    """Testy przygotowania danych"""

    def test_basic_split(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y, test_size=0.2)
        assert len(X_train) > 0
        assert len(X_test) > 0
        assert len(y_train) > 0
        assert len(y_test) > 0

    def test_feature_names_stored(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        trainer.prepare_data(X, y)
        assert trainer.feature_names == ['feature1', 'feature2', 'feature3']

    def test_scaler_created(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        trainer.prepare_data(X, y)
        assert trainer.scaler is not None

    def test_single_class_no_crash(self, trainer, single_class_dataset):
        """Bug fix: stratify=y z jedną klasą nie powinno crashować"""
        X, y = single_class_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(
            X, y, test_size=0.2, balance_data=False
        )
        assert len(X_train) > 0
        assert len(X_test) > 0

    def test_smote_applied_with_two_classes(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(
            X, y, balance_data=True
        )
        assert len(X_train) == len(y_train)
        assert trainer._X_calib_scaled is not None
        assert len(X_train) >= 60

    def test_smote_skipped_single_class(self, trainer, single_class_dataset):
        """SMOTE nie powinien być stosowany z jedną klasą"""
        X, y = single_class_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(
            X, y, balance_data=True
        )
        assert len(X_train) > 0


class TestTrainRandomForest:
    """Testy trenowania Random Forest"""

    def test_train_basic(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
        model = trainer.train_random_forest(X_train, y_train)
        assert model is not None
        assert trainer.random_forest is not None

    def test_train_predictions(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
        model = trainer.train_random_forest(X_train, y_train)
        predictions = model.predict(X_test)
        assert len(predictions) == len(X_test)
        assert set(predictions).issubset({0, 1})


class TestTrainIsolationForest:
    """Testy trenowania Isolation Forest"""

    def test_train_basic(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, _, _, _ = trainer.prepare_data(X, y)
        model = trainer.train_isolation_forest(X_train)
        assert model is not None
        assert trainer.isolation_forest is not None

    def test_predictions_format(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, _, _ = trainer.prepare_data(X, y)
        model = trainer.train_isolation_forest(X_train)
        predictions = model.predict(X_test)
        assert set(predictions).issubset({-1, 1})


class TestEvaluate:
    """Testy ewaluacji"""

    def test_evaluate_rf(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
        trainer.train_random_forest(X_train, y_train)
        results = trainer.evaluate(X_test, y_test)
        assert 'random_forest' in results
        assert 'classification_report' in results['random_forest']
        assert 'confusion_matrix' in results['random_forest']

    def test_evaluate_if(self, trainer, balanced_dataset):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
        trainer.train_isolation_forest(X_train)
        results = trainer.evaluate(X_test, y_test)
        assert 'isolation_forest' in results


class TestSaveModels:
    """Testy zapisywania modeli"""

    def test_save_and_load(self, trainer, balanced_dataset, tmp_path):
        X, y = balanced_dataset
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
        trainer.train_random_forest(X_train, y_train)
        trainer.train_isolation_forest(X_train)
        trainer.save_models()

        assert (tmp_path / "random_forest_classifier.joblib").exists()
        assert (tmp_path / "isolation_forest_anomaly.joblib").exists()
        assert (tmp_path / "scaler.joblib").exists()
        assert (tmp_path / "feature_names.joblib").exists()


class TestFullPipeline:
    """Testy pełnego pipeline'u"""

    def test_full_pipeline(self, trainer, balanced_dataset, tmp_path):
        X, y = balanced_dataset
        results = trainer.full_training_pipeline(X, y)

        assert 'random_forest' in results
        assert 'isolation_forest' in results
        assert (tmp_path / "evaluation_results.json").exists()

    def test_full_pipeline_small_dataset(self, trainer, small_dataset, tmp_path):
        X, y = small_dataset
        results = trainer.full_training_pipeline(X, y)
        assert results is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
