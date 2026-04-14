"""
Machine Learning Models Module
Moduł modeli uczenia maszynowego
"""

from .train import ModelTrainer
from .predict import EmailClassifier
from .model_manager import ModelManager

__all__ = ['ModelTrainer', 'EmailClassifier', 'ModelManager']

