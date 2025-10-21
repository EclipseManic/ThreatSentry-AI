"""Model package exports - bridge to advanced training orchestrator

This module exposes the training and prediction helpers used by the rest
of the application but delegates implementation to the advanced
`ModelTrainingOrchestrator`/`EnsembleModel` APIs.
"""
from .training_orchestrator import ModelTrainingOrchestrator
from .advanced_model import EnsembleModel
from logger import get_logger
from config import MODEL_PATH
from typing import Optional
import os

logger = get_logger("model")


def train_and_save_model() -> bool:
	"""Train using the advanced orchestrator and save model/metadata.

	Returns True on successful training, False otherwise.
	"""
	orch = ModelTrainingOrchestrator()
	return orch.train_model()


def load_training_data():
	"""Prepare training data via the orchestrator's feature engineering.

	Returns (X, y) or (None, None) when no data is available.
	"""
	orch = ModelTrainingOrchestrator()
	return orch.prepare_training_data()


def predict_and_store(model: Optional[EnsembleModel] = None):
	"""Load existing model (if any) and run batch prediction to update DB.

	The optional `model` parameter is accepted for API-compatibility but
	currently ignored since orchestrator manages loading/saving.
	"""
	orch = ModelTrainingOrchestrator.load_latest_model()
	orch.predict_and_update()


def load_model():
	"""Load and return the advanced EnsembleModel instance if present."""
	if not os.path.exists(MODEL_PATH):
		logger.warning("Model not found at %s", MODEL_PATH)
		return None
	return EnsembleModel.load_model(MODEL_PATH)


__all__ = ["train_and_save_model", "load_training_data", "predict_and_store", "load_model", "ModelTrainingOrchestrator", "EnsembleModel"]
