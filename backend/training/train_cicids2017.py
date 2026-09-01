#!/usr/bin/env python3
"""
SIH26145 — CICIDS2017 Random Forest Training Script.

Trains a binary BENIGN/ATTACK classifier using real CICIDS2017 flow data.

Uses stratified sampling from the full 2M+ row dataset to manage memory
while preserving class distribution.

PREREQUISITES:
  Run prepare_cicids2017.py first:
    cd backend
    python -m training.prepare_cicids2017 /path/to/csvs/

OUTPUT:
    backend/ml_models/rf_cicids2017.joblib
    backend/ml_models/scaler_cicids2017.joblib
    backend/ml_models/label_encoder_cicids2017.joblib
    backend/ml_models/model_info_cicids2017.joblib

USAGE:
    cd backend
    python -m training.train_cicids2017
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
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Add backend/ to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.prepare_cicids2017 import ML_FEATURE_COLUMNS

# ── Configuration ─────────────────────────────────────────────────
CLEANED_CSV = Path(__file__).resolve().parent / "data" / "cicids2017_cleaned.csv"
MODEL_DIR = Path(__file__).resolve().parent.parent / "ml_models"

RANDOM_SEED = 42
MAX_TRAINING_ROWS = 500_000  # Stratified sample limit for memory efficiency

# Random Forest hyperparameters
RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": 25,
    "min_samples_split": 10,
    "min_samples_leaf": 4,
    "max_features": "sqrt",
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
    "class_weight": "balanced",
}


def load_cleaned_data() -> pd.DataFrame:
    """Load the cleaned CICIDS2017 dataset."""
    if not CLEANED_CSV.exists():
        print(f"ERROR: Cleaned dataset not found at {CLEANED_CSV}")
        print("Run prepare_cicids2017.py first:")
        print("  cd backend")
        print("  python -m training.prepare_cicids2017 /path/to/csvs/")
        sys.exit(1)

    print(f"Loading cleaned dataset from {CLEANED_CSV}...")
    df = pd.read_csv(CLEANED_CSV)
    print(f"  Rows: {len(df)}")
    print(f"  Columns: {list(df.columns)}")
    return df


def train_model() -> dict:
    """Train the CICIDS2017 Random Forest model and save all artifacts."""
    print("=" * 60)
    print("SIH26145 — CICIDS2017 Random Forest Training")
    print("=" * 60)

    # ── Step 1: Load data ─────────────────────────────────────────
    print("\n[1/8] Loading cleaned CICIDS2017 data...")
    full_df = load_cleaned_data()
    total_rows = len(full_df)

    # Verify features
    available = [c for c in ML_FEATURE_COLUMNS if c in full_df.columns]
    if len(available) < len(ML_FEATURE_COLUMNS):
        missing = [c for c in ML_FEATURE_COLUMNS if c not in full_df.columns]
        print(f"  WARNING: Missing features: {missing}")

    feature_cols = available
    print(f"  Using {len(feature_cols)} features: {feature_cols}")

    # ── Step 2: Stratified sample for memory efficiency ───────────
    print(f"\n[2/8] Stratified sampling (max {MAX_TRAINING_ROWS} rows)...")
    if total_rows > MAX_TRAINING_ROWS:
        df = full_df.groupby("label", group_keys=False).apply(
            lambda x: x.sample(
                n=min(len(x), int(MAX_TRAINING_ROWS * len(x) / total_rows)),
                random_state=RANDOM_SEED,
            ),
            include_groups=False,
        )
        # Re-add label column since include_groups=False drops it
        # Actually, let's use a simpler approach
        del full_df  # free memory
        del df

        # Reload and sample properly
        full_df = load_cleaned_data()
        sampled_dfs = []
        for label in full_df["label"].unique():
            subset = full_df[full_df["label"] == label]
            n_sample = min(len(subset), int(MAX_TRAINING_ROWS * len(subset) / total_rows))
            sampled_dfs.append(subset.sample(n=n_sample, random_state=RANDOM_SEED))
        df = pd.concat(sampled_dfs, ignore_index=True)
        del full_df
    else:
        df = full_df

    print(f"  Training set size: {len(df)} rows")
    for label in df["label"].unique():
        count = (df["label"] == label).sum()
        print(f"    {label}: {count} ({count/len(df)*100:.1f}%)")

    # ── Step 3: Prepare X, y ──────────────────────────────────────
    print("\n[3/8] Preparing features and labels...")
    X = df[feature_cols].values.astype(np.float64)
    y_raw = df["label"].values

    # Replace any remaining inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)
    class_names = list(label_encoder.classes_)

    print(f"  Classes: {class_names}")

    # ── Step 4: Split data ────────────────────────────────────────
    print("\n[4/8] Splitting data (80/20, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # Check for duplicate rows leaking between train/test
    train_set = set(map(tuple, X_train.tolist()))
    test_set = set(map(tuple, X_test.tolist()))
    overlap = train_set & test_set
    print(f"  Duplicate rows in train/test: {len(overlap)}")

    # ── Step 5: Scale features ────────────────────────────────────
    print("\n[5/8] Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ── Step 6: Train Random Forest ───────────────────────────────
    print("\n[6/8] Training Random Forest...")
    print(f"  Parameters: {RF_PARAMS}")
    start_time = time.time()
    clf = RandomForestClassifier(**RF_PARAMS)
    clf.fit(X_train_scaled, y_train)
    train_time = time.time() - start_time
    print(f"  Training time: {train_time:.2f}s")

    # ── Step 7: Evaluate ──────────────────────────────────────────
    print("\n[7/8] Evaluating on test set...")
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

    try:
        if len(class_names) == 2:
            roc_auc = roc_auc_score(y_test, y_proba[:, 1])
        else:
            roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr")
        print(f"  ROC-AUC:   {roc_auc:.4f}")
    except Exception:
        roc_auc = 0.0
        print(f"  ROC-AUC:   N/A")

    print(f"\n  ── Per-Class Classification Report ──")
    print(classification_report(y_test, y_pred, target_names=class_names))

    print(f"  ── Confusion Matrix ──")
    cm = confusion_matrix(y_test, y_pred)
    header = "  " + "".join(f"{name[:12]:>14}" for name in class_names)
    print(header)
    for i, row in enumerate(cm):
        row_str = "".join(f"{val:>14}" for val in row)
        print(f"  {class_names[i][:12]:>12} {row_str}")

    print(f"\n  ── Feature Importance ──")
    importances = clf.feature_importances_
    for feat, imp in sorted(zip(feature_cols, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"  {feat:<30} {imp:.4f} {bar}")

    # ── Step 8: Save model artifacts ──────────────────────────────
    print("\n[8/8] Saving model artifacts...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_version = "2.0-cicids2017-real"
    model_name = "RandomForest-CICIDS2017-Real"

    clf_path = MODEL_DIR / "rf_cicids2017.joblib"
    joblib.dump(clf, clf_path)
    print(f"  Saved: {clf_path} ({os.path.getsize(clf_path):,} bytes)")

    scaler_path = MODEL_DIR / "scaler_cicids2017.joblib"
    joblib.dump(scaler, scaler_path)
    print(f"  Saved: {scaler_path}")

    encoder_path = MODEL_DIR / "label_encoder_cicids2017.joblib"
    joblib.dump(label_encoder, encoder_path)
    print(f"  Saved: {encoder_path}")

    model_info = {
        "model_name": model_name,
        "model_version": model_version,
        "model_type": "RandomForestClassifier",
        "model_source": "CICIDS2017",
        "feature_names": feature_cols,
        "num_features": len(feature_cols),
        "classes": class_names,
        "num_classes": len(class_names),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "duplicate_overlap": int(len(overlap)),
        "random_seed": RANDOM_SEED,
        "rf_params": RF_PARAMS,
        "metrics": {
            "accuracy": round(float(accuracy), 4),
            "precision_weighted": round(float(precision), 4),
            "recall_weighted": round(float(recall), 4),
            "f1_weighted": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
        },
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test, y_pred, target_names=class_names, output_dict=True
        ),
        "training_time_seconds": round(train_time, 2),
        "training_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": "CICIDS2017 (real labeled network flow data)",
        "data_source_detail": "HuggingFace bvk/CICIDS-2017, 5 days of captured traffic",
        "data_transparency": (
            "This model is trained on the CICIDS2017 dataset "
            "(https://www.unb.ca/cic/datasets/ids-2017.html) containing "
            "real labeled network flows from CICFlowMeter. Binary classification: "
            "BENIGN vs ATTACK. NOT synthetic data."
        ),
        "total_dataset_rows": total_rows,
        "attack_types_included": [
            "DDoS", "DoS Hulk", "DoS GoldenEye", "DoS Slowloris",
            "DoS Slowhttptest", "Heartbleed", "FTP-Patator", "SSH-Patator",
            "Web Attack Brute Force", "Web Attack XSS", "Web Attack SQL Injection",
            "Infiltration", "Portscan", "Botnet",
        ],
    }
    info_path = MODEL_DIR / "model_info_cicids2017.joblib"
    joblib.dump(model_info, info_path)
    print(f"  Saved: {info_path}")

    print("\n" + "=" * 60)
    print("CICIDS2017 TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model: {model_name} v{model_version}")
    print(f"  Data source: CICIDS2017 (real labeled network flow data)")
    print(f"  Total dataset: {total_rows} rows")
    print(f"  Training: {len(X_train)}, Test: {len(X_test)}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"  Training time: {train_time:.2f}s")

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "train_time": train_time,
        "model_dir": str(MODEL_DIR),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "num_features": len(feature_cols),
    }


if __name__ == "__main__":
    results = train_model()
    sys.exit(0 if results["accuracy"] > 0.8 else 1)
