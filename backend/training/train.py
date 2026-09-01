#!/usr/bin/env python3
"""
SIH26145 Model Training Script — Random Forest Network Threat Classifier.

This script:
  1. Generates synthetic labeled flow data (CICIDS2017-like patterns)
  2. Preprocesses features (StandardScaler for normalization)
  3. Trains a Random Forest classifier
  4. Evaluates on held-out test set
  5. Reports accuracy, precision, recall, F1, confusion matrix
  6. Saves model + scaler + label encoder + metadata to ml_models/

TRANSPARENCY NOTE:
  Training data is SYNTHETIC, generated to mimic CICIDS2017 statistical
  patterns. This is NOT the actual CICIDS2017 dataset. A production
  system should train on real labeled network flow data.

Usage:
    cd backend
    python -m training.train

Output:
    backend/ml_models/rf_classifier.joblib
    backend/ml_models/scaler.joblib
    backend/ml_models/label_encoder.joblib
    backend/ml_models/model_info.joblib
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Add backend/ to path so we can import training modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.generate_data import FEATURE_COLUMNS, generate_dataset

# ── Configuration ─────────────────────────────────────────────────
MODEL_DIR = Path(__file__).resolve().parent.parent / "ml_models"
RANDOM_SEED = 42
TEST_SIZE = 0.2
SAMPLES_PER_CLASS = 2000

# Random Forest hyperparameters
RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
    "class_weight": "balanced",
}


def train_model() -> dict:
    """
    Train the Random Forest model and save all artifacts.

    Returns:
        dict with training metrics and model info.
    """
    print("=" * 60)
    print("SIH26145 — Random Forest Training Pipeline")
    print("=" * 60)

    # ── Step 1: Generate data ─────────────────────────────────────
    print("\n[1/7] Generating synthetic training data...")
    df = generate_dataset(samples_per_class=SAMPLES_PER_CLASS, seed=RANDOM_SEED)
    print(f"  Total samples: {len(df)}")
    print(f"  Classes: {df['label'].nunique()}")
    print(f"  Features: {len(FEATURE_COLUMNS)}")
    print(f"\n  Class distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"    {label}: {count}")

    X = df[FEATURE_COLUMNS].values
    y_raw = df["label"].values

    # ── Step 2: Encode labels ─────────────────────────────────────
    print("\n[2/7] Encoding labels...")
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)
    class_names = list(label_encoder.classes_)
    print(f"  Classes: {class_names}")

    # ── Step 3: Split data ────────────────────────────────────────
    print(f"\n[3/7] Splitting data (test_size={TEST_SIZE})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # ── Step 4: Scale features ────────────────────────────────────
    print("\n[4/7] Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print(f"  Feature means (first 3): {scaler.mean_[:3].round(3)}")
    print(f"  Feature stds  (first 3): {scaler.scale_[:3].round(3)}")

    # ── Step 5: Train Random Forest ───────────────────────────────
    print("\n[5/7] Training Random Forest...")
    print(f"  Parameters: {RF_PARAMS}")
    start_time = time.time()
    clf = RandomForestClassifier(**RF_PARAMS)
    clf.fit(X_train_scaled, y_train)
    train_time = time.time() - start_time
    print(f"  Training time: {train_time:.2f}s")
    print(f"  Trees: {clf.n_estimators}")
    print(f"  Max depth: {clf.max_depth}")

    # ── Step 6: Evaluate ──────────────────────────────────────────
    print("\n[6/7] Evaluating on test set...")
    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted")
    recall = recall_score(y_test, y_pred, average="weighted")
    f1 = f1_score(y_test, y_pred, average="weighted")

    print(f"\n  ── Overall Metrics ──")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")

    print(f"\n  ── Per-Class Classification Report ──")
    print(classification_report(y_test, y_pred, target_names=class_names))

    print(f"  ── Confusion Matrix ──")
    cm = confusion_matrix(y_test, y_pred)
    # Print with labels
    header = "  " + "".join(f"{name[:12]:>14}" for name in class_names)
    print(header)
    for i, row in enumerate(cm):
        row_str = "".join(f"{val:>14}" for val in row)
        print(f"  {class_names[i][:12]:>12} {row_str}")

    # ── Step 7: Save model artifacts ──────────────────────────────
    print("\n[7/7] Saving model artifacts...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_version = "1.0"
    model_name = "RandomForest-SIH26145"

    # Save classifier
    clf_path = MODEL_DIR / "rf_classifier.joblib"
    joblib.dump(clf, clf_path)
    print(f"  Saved: {clf_path}")

    # Save scaler
    scaler_path = MODEL_DIR / "scaler.joblib"
    joblib.dump(scaler, scaler_path)
    print(f"  Saved: {scaler_path}")

    # Save label encoder
    encoder_path = MODEL_DIR / "label_encoder.joblib"
    joblib.dump(label_encoder, encoder_path)
    print(f"  Saved: {encoder_path}")

    # Save model info
    model_info = {
        "model_name": model_name,
        "model_version": model_version,
        "model_type": "RandomForestClassifier",
        "feature_names": FEATURE_COLUMNS,
        "num_features": len(FEATURE_COLUMNS),
        "classes": class_names,
        "num_classes": len(class_names),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "samples_per_class": SAMPLES_PER_CLASS,
        "random_seed": RANDOM_SEED,
        "rf_params": RF_PARAMS,
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision_weighted": round(precision, 4),
            "recall_weighted": round(recall, 4),
            "f1_weighted": round(f1, 4),
        },
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test, y_pred, target_names=class_names, output_dict=True
        ),
        "training_time_seconds": round(train_time, 2),
        "training_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": "Synthetic (CICIDS2017-like patterns)",
        "data_transparency": (
            "Training data is synthetic, generated to mimic CICIDS2017 "
            "statistical distributions. NOT the actual CICIDS2017 dataset."
        ),
    }
    info_path = MODEL_DIR / "model_info.joblib"
    joblib.dump(model_info, info_path)
    print(f"  Saved: {info_path}")

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model: {model_name} v{model_version}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Training time: {train_time:.2f}s")
    print(f"  Artifacts saved to: {MODEL_DIR}")
    print(f"\n  Model files:")
    print(f"    {MODEL_DIR / 'rf_classifier.joblib'}")
    print(f"    {MODEL_DIR / 'scaler.joblib'}")
    print(f"    {MODEL_DIR / 'label_encoder.joblib'}")
    print(f"    {MODEL_DIR / 'model_info.joblib'}")

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "train_time": train_time,
        "model_dir": str(MODEL_DIR),
    }


if __name__ == "__main__":
    results = train_model()
    sys.exit(0 if results["accuracy"] > 0.8 else 1)
