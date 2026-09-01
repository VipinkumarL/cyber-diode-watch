"""
SIH26145 ML Model Loader.

Loads trained Random Forest models and associated metadata from disk.

Supports two model types:
  1. CICIDS2017 model (rf_cicids2017.joblib) — real CICIDS2017 data
  2. Synthetic model (rf_classifier.joblib) — fallback synthetic data

Model files are expected in backend/ml_models/:
  For CICIDS2017:
    - rf_cicids2017.joblib
    - scaler_cicids2017.joblib
    - label_encoder_cicids2017.joblib
    - model_info_cicids2017.joblib
  For synthetic (legacy):
    - rf_classifier.joblib
    - scaler.joblib
    - label_encoder.joblib
    - model_info.joblib

Priority: CICIDS2017 model is preferred over synthetic.
If neither is available, is_model_loaded() returns False.
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

# Current loaded model state
_model: Any = None
_scaler: Any = None
_label_encoder: Any = None
_model_info: dict[str, Any] = {}
_model_dir: str = _DEFAULT_MODEL_DIR
_model_source: str = ""  # "CICIDS2017" or "synthetic"


def _try_load_model(model_dir: str, prefix: str) -> bool:
    """
    Try to load model files with a given prefix.

    Args:
        model_dir: Directory containing model files.
        prefix: File prefix (e.g., "rf_cicids2017" or "rf_classifier").

    Returns:
        True if loaded successfully, False otherwise.
    """
    global _model, _scaler, _label_encoder, _model_info, _model_source

    # Determine file names based on prefix
    if prefix == "rf_cicids2017":
        classifier_path = os.path.join(model_dir, "rf_cicids2017.joblib")
        scaler_path = os.path.join(model_dir, "scaler_cicids2017.joblib")
        encoder_path = os.path.join(model_dir, "label_encoder_cicids2017.joblib")
        info_path = os.path.join(model_dir, "model_info_cicids2017.joblib")
    else:
        classifier_path = os.path.join(model_dir, "rf_classifier.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")
        encoder_path = os.path.join(model_dir, "label_encoder.joblib")
        info_path = os.path.join(model_dir, "model_info.joblib")

    # Check all files exist
    for path in [classifier_path, scaler_path, encoder_path, info_path]:
        if not os.path.exists(path):
            return False

    try:
        _model = joblib.load(classifier_path)
        _scaler = joblib.load(scaler_path)
        _label_encoder = joblib.load(encoder_path)
        _model_info = joblib.load(info_path)

        # Determine source
        _model_source = _model_info.get("model_source", "synthetic")

        logger.info(
            "ML model loaded: %s (%s) (%d classes, %d features)",
            _model_info.get("model_name", "RandomForest"),
            _model_source,
            len(_model_info.get("classes", [])),
            len(_model_info.get("feature_names", [])),
        )
        return True

    except Exception as exc:
        logger.error("Failed to load ML model (%s): %s", prefix, exc)
        _model = None
        _scaler = None
        _label_encoder = None
        _model_info = {}
        _model_source = ""
        return False


def load_model(model_dir: Optional[str] = None) -> bool:
    """
    Load the trained model from disk.

    Priority: CICIDS2017 model → synthetic model → None.

    Args:
        model_dir: Directory containing model files.
                   Defaults to backend/ml_models/.

    Returns:
        True if any model loaded successfully, False otherwise.
    """
    global _model_dir

    if model_dir is not None:
        _model_dir = model_dir
    else:
        _model_dir = _DEFAULT_MODEL_DIR

    # Reset state
    global _model, _scaler, _label_encoder, _model_info, _model_source
    _model = None
    _scaler = None
    _label_encoder = None
    _model_info = {}
    _model_source = ""

    # Try CICIDS2017 model first (preferred)
    if _try_load_model(_model_dir, "rf_cicids2017"):
        logger.info("Loaded CICIDS2017 model (real data)")
        return True

    # Fall back to synthetic model
    if _try_load_model(_model_dir, "rf_classifier"):
        logger.info("Loaded synthetic model (fallback)")
        return True

    logger.warning("No ML model files found in %s", _model_dir)
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


def get_model_source() -> str:
    """Return the model source: 'CICIDS2017', 'synthetic', or ''."""
    return _model_source
