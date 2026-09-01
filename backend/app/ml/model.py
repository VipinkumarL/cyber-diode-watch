"""
SIH26145 ML Model Loader.

Loads the trained Random Forest model and associated metadata
(label encoder, scaler, feature names, training info) from disk.

Model files are expected in backend/ml_models/:
  - rf_classifier.joblib   — trained RandomForestClassifier
  - scaler.joblib          — fitted StandardScaler
  - label_encoder.joblib   — fitted LabelEncoder
  - model_info.joblib      — dict with feature names, class names, metrics

If any file is missing, is_model_loaded() returns False and
the backend continues to function with baseline detectors only.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import joblib

logger = logging.getLogger(__name__)

# Default model directory (relative to backend/)
_DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "ml_models",
)

_model: Any = None
_scaler: Any = None
_label_encoder: Any = None
_model_info: dict[str, Any] = {}
_model_dir: str = _DEFAULT_MODEL_DIR


def load_model(model_dir: Optional[str] = None) -> bool:
    """
    Load the trained model from disk.

    Args:
        model_dir: Directory containing model files.
                   Defaults to backend/ml_models/.

    Returns:
        True if model loaded successfully, False otherwise.
    """
    global _model, _scaler, _label_encoder, _model_info, _model_dir

    if model_dir is not None:
        _model_dir = model_dir
    else:
        _model_dir = _DEFAULT_MODEL_DIR

    classifier_path = os.path.join(_model_dir, "rf_classifier.joblib")
    scaler_path = os.path.join(_model_dir, "scaler.joblib")
    encoder_path = os.path.join(_model_dir, "label_encoder.joblib")
    info_path = os.path.join(_model_dir, "model_info.joblib")

    # Check all files exist
    for path in [classifier_path, scaler_path, encoder_path, info_path]:
        if not os.path.exists(path):
            logger.warning("ML model file not found: %s", path)
            _model = None
            _scaler = None
            _label_encoder = None
            _model_info = {}
            return False

    try:
        _model = joblib.load(classifier_path)
        _scaler = joblib.load(scaler_path)
        _label_encoder = joblib.load(encoder_path)
        _model_info = joblib.load(info_path)

        logger.info(
            "ML model loaded: %s (%d classes, %d features)",
            _model_info.get("model_name", "RandomForest"),
            len(_model_info.get("classes", [])),
            len(_model_info.get("feature_names", [])),
        )
        return True

    except Exception as exc:
        logger.error("Failed to load ML model: %s", exc)
        _model = None
        _scaler = None
        _label_encoder = None
        _model_info = {}
        return False


def is_model_loaded() -> bool:
    """Check whether the ML model is loaded and ready for inference."""
    return _model is not None and _label_encoder is not None and _scaler is not None


def get_model() -> Any:
    """Return the loaded model (or None)."""
    return _model


def get_scaler() -> Any:
    """Return the fitted StandardScaler (or None)."""
    return _scaler


def get_label_encoder() -> Any:
    """Return the fitted label encoder (or None)."""
    return _label_encoder


def get_model_info() -> dict[str, Any]:
    """Return model metadata (feature names, classes, metrics, etc.)."""
    return dict(_model_info)


def get_model_dir() -> str:
    """Return the current model directory path."""
    return _model_dir
