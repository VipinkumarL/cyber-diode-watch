#!/usr/bin/env python3
"""
SIH26145 — CICIDS2017 Data Preparation Script.

Prepares the real CICIDS2017 dataset for training a Random Forest
binary classifier (BENIGN vs ATTACK).

Supports two sources:
  1. Official CICIDS2017 MachineLearningCSV (original column names)
  2. HuggingFace bvk/CICIDS-2017 (slightly different column names)

INPUT:
    A directory containing CICIDS2017 CSV files, OR a single CSV file.

OUTPUT:
    backend/data/cicids2017_cleaned.csv
    backend/data/feature_info.joblib

USAGE:
    cd backend
    python training/prepare_cicids2017.py /path/to/csvs/
    python training/prepare_cicids2017.py backend/data/
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ── Column name normalization ────────────────────────────────────
# Maps ALL known CICIDS2017 column variants to clean snake_case names.
# Both the official UNB naming and HuggingFace bvk/CICIDS-2017 naming.

_COLUMN_ALIASES: dict[str, str] = {
    # Official UNB CICIDS2017 names
    "flow duration": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_backward_packets",
    "fwd packets length total": "fwd_packets_length_total",
    "bwd packets length total": "bwd_packets_length_total",
    "flow bytes/s": "flow_bytes_s",
    "flow packets/s": "flow_packets_s",
    "packet length mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "fwd packet length mean": "fwd_packet_length_mean",
    "bwd packet length mean": "bwd_packet_length_mean",
    "source port": "source_port",
    "destination port": "destination_port",
    "label": "label",

    # HuggingFace bvk/CICIDS-2017 names
    "total fwd packet": "total_fwd_packets",
    "total bwd packets": "total_backward_packets",
    "total length of fwd packet": "fwd_packets_length_total",
    "total length of bwd packet": "bwd_packets_length_total",
    "src port": "source_port",
    "dst port": "destination_port",
    "src ip dec": "source_ip_dec",
    "dst ip dec": "destination_ip_dec",
    "attempted category": "attempted_category",
    "total tcp flow time": "total_tcp_flow_time",
    "icmp code": "icmp_code",
    "icmp type": "icmp_type",
    "fwd rst flags": "fwd_rst_flags",
    "bwd rst flags": "bwd_rst_flags",
    "cwr flag count": "cwr_flag_count",
    "ece flag count": "ece_flag_count",
    "fwd init win bytes": "init_win_bytes_forward",
    "bwd init win bytes": "init_win_bytes_backward",
    "fwd act data pkts": "act_data_pkt_fwd",
    "fwd seg size min": "min_seg_size_forward",
    "fwd segment size avg": "avg_fwd_segment_size",
    "bwd segment size avg": "avg_bwd_segment_size",
    "average packet size": "avg_packet_size",
    "down/up ratio": "down_up_ratio",
}


# ── ML feature selection ─────────────────────────────────────────
# 12 features selected from CICIDS2017 that map to our NetworkFlow schema.
# Feature order MUST be identical during training and inference.

ML_FEATURE_COLUMNS: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_bytes",              # derived: fwd + bwd length
    "flow_bytes_s",
    "flow_packets_s",
    "destination_port",
    "source_port",
    "packet_length_mean",
    "packet_length_std",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
]

# CICIDS2017 attack label → binary
_ATTACK_LABELS: set[str] = {
    "ddos",
    "dos slowloris",
    "dos slowhttptest",
    "dos hulk",
    "dos goldeneye",
    "dos slowloris - attempted",
    "dos slowhttptest - attempted",
    "dos hulk - attempted",
    "dos goldeneye - attempted",
    "heartbleed",
    "web attack brute force",
    "web attack brute force - attempted",
    "web attack xss",
    "web attack xss - attempted",
    "web attack sql injection",
    "web attack sql injection - attempted",
    "infiltration",
    "infiltration - portscan",
    "infiltration - attempted",
    "botnet",
    "botnet - attempted",
    "portscan",
    "ftp-patator",
    "ftp-patator - attempted",
    "ssh-patator",
    "ssh-patator - attempted",
}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize CICIDS2017 column names to clean snake_case."""
    rename_map: dict[str, str] = {}
    for col in df.columns:
        cleaned = col.strip().lower()
        if cleaned in _COLUMN_ALIASES:
            rename_map[col] = _COLUMN_ALIASES[cleaned]
        else:
            rename_map[col] = cleaned.replace(" ", "_")
    return df.rename(columns=rename_map)


def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS2017 labels to binary BENIGN / ATTACK."""
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].apply(
        lambda x: "ATTACK" if x in _ATTACK_LABELS else "BENIGN"
    )
    return df


def derive_total_bytes(df: pd.DataFrame) -> pd.DataFrame:
    """Derive total bytes from forward + backward packet length totals."""
    if "fwd_packets_length_total" in df.columns and "bwd_packets_length_total" in df.columns:
        df["total_bytes"] = pd.to_numeric(df["fwd_packets_length_total"], errors="coerce").fillna(0) + \
                            pd.to_numeric(df["bwd_packets_length_total"], errors="coerce").fillna(0)
    elif "flow_bytes_s" in df.columns and "flow_duration" in df.columns:
        df["total_bytes"] = pd.to_numeric(df["flow_bytes_s"], errors="coerce").fillna(0) * \
                            pd.to_numeric(df["flow_duration"], errors="coerce").fillna(0)
    else:
        df["total_bytes"] = 0.0
    return df


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Clean ML feature columns: coerce to float, replace inf/nan."""
    for col in ML_FEATURE_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            df[col] = 0.0

    # Replace inf with NaN, then fill NaN with 0
    for col in ML_FEATURE_COLUMNS:
        df[col] = df[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    return df


def load_csv_files(path: str) -> list[str]:
    """Return list of CSV file paths."""
    path_obj = Path(path)

    if path_obj.is_file() and path_obj.suffix == ".csv":
        return [str(path_obj)]

    if path_obj.is_dir():
        csv_files = sorted(path_obj.glob("*.csv"))
        if not csv_files:
            print(f"ERROR: No CSV files found in {path_obj}")
            sys.exit(1)
        print(f"Found {len(csv_files)} CSV files in {path_obj}:")
        for f in csv_files:
            size_mb = os.path.getsize(f) / 1024 / 1024
            print(f"  {f.name} ({size_mb:.1f} MB)")
        return [str(f) for f in csv_files]

    print(f"ERROR: {path_obj} is not a valid CSV file or directory")
    sys.exit(1)


def prepare_dataset(csv_path: str, output_dir: str | None = None) -> pd.DataFrame:
    """
    Full preparation pipeline for CICIDS2017 data.
    Processes files one at a time for memory efficiency.
    """
    print("=" * 60)
    print("SIH26145 — CICIDS2017 Data Preparation")
    print("=" * 60)

    # Determine output directory
    if output_dir is None:
        output_dir = str(Path(__file__).resolve().parent / "data")
    os.makedirs(output_dir, exist_ok=True)

    # Get list of CSV files
    csv_files = load_csv_files(csv_path)

    # Step 1: Inspect first file to determine columns
    print("\n[1/7] Inspecting dataset columns...")
    sample_df = pd.read_csv(csv_files[0], nrows=5, low_memory=False)
    sample_df = normalize_columns(sample_df)
    print(f"  Raw columns ({len(sample_df.columns)}):")
    for i, col in enumerate(sample_df.columns):
        print(f"    {i+1:2d}. {repr(col)}")

    # Step 2: Process each file one at a time
    print("\n[2/7] Processing files (one at a time for memory efficiency)...")
    all_dfs = []
    total_rows = 0
    total_attack = 0
    total_benign = 0

    for csv_file in csv_files:
        print(f"\n  Loading {os.path.basename(csv_file)}...")
        df = pd.read_csv(csv_file, low_memory=False)
        print(f"    Raw: {len(df)} rows, {len(df.columns)} cols")

        # Normalize columns
        df = normalize_columns(df)

        # Normalize labels
        df = normalize_labels(df)

        # Count
        attack_count = (df["label"] == "ATTACK").sum()
        benign_count = (df["label"] == "BENIGN").sum()
        total_attack += attack_count
        total_benign += benign_count
        print(f"    BENIGN: {benign_count}, ATTACK: {attack_count}")

        # Derive total_bytes
        df = derive_total_bytes(df)

        # Select only needed columns
        available_features = [c for c in ML_FEATURE_COLUMNS if c in df.columns]
        keep_cols = available_features + ["label"]
        df = df[keep_cols].copy()

        # Clean features
        df = clean_features(df)

        # Remove duplicates within this file
        before = len(df)
        df = df.drop_duplicates()
        after = len(df)
        if before - after > 0:
            print(f"    Removed {before - after} duplicates")

        total_rows += len(df)
        all_dfs.append(df)

        # Free memory
        del df

    print(f"\n  Total processed rows: {total_rows}")
    print(f"  Total BENIGN: {total_benign} ({total_benign/total_rows*100:.1f}%)")
    print(f"  Total ATTACK: {total_attack} ({total_attack/total_rows*100:.1f}%)")

    # Step 3: Concatenate all files
    print("\n[3/7] Concatenating all files...")
    full_df = pd.concat(all_dfs, ignore_index=True)
    del all_dfs  # free memory

    # Remove cross-file duplicates
    before = len(full_df)
    full_df = full_df.drop_duplicates()
    after = len(full_df)
    print(f"  After cross-file dedup: {len(full_df)} (removed {before - after})")

    # Step 4: Final NaN/inf cleanup
    print("\n[4/7] Final cleanup...")
    for col in ML_FEATURE_COLUMNS:
        if col in full_df.columns:
            full_df[col] = full_df[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # Verify features
    print(f"\n[5/7] Feature verification:")
    for feat in ML_FEATURE_COLUMNS:
        if feat in full_df.columns:
            stats = full_df[feat].describe()
            print(f"  ✓ {feat:<30} mean={stats['mean']:.2f}, std={stats['std']:.2f}, "
                  f"min={stats['min']:.2f}, max={stats['max']:.2f}")
        else:
            print(f"  ✗ {feat:<30} MISSING")

    # Step 6: Save cleaned dataset
    print(f"\n[6/7] Saving cleaned dataset...")
    csv_output = os.path.join(output_dir, "cicids2017_cleaned.csv")
    full_df.to_csv(csv_output, index=False)
    print(f"  Saved: {csv_output}")
    print(f"  Shape: {full_df.shape}")
    size_mb = os.path.getsize(csv_output) / 1024 / 1024
    print(f"  Size: {size_mb:.1f} MB")

    # Save feature info
    feature_info = {
        "feature_columns": ML_FEATURE_COLUMNS,
        "num_features": len(ML_FEATURE_COLUMNS),
        "label_column": "label",
        "classes": ["BENIGN", "ATTACK"],
        "data_source": "CICIDS2017",
        "data_source_detail": "HuggingFace bvk/CICIDS-2017",
        "num_rows": len(full_df),
        "class_distribution": full_df["label"].value_counts().to_dict(),
    }
    info_path = os.path.join(output_dir, "feature_info.joblib")
    joblib.dump(feature_info, info_path)
    print(f"  Saved: {info_path}")

    # Step 7: Summary
    print(f"\n[7/7] Summary")
    print("=" * 60)
    print("PREPARATION COMPLETE")
    print("=" * 60)
    print(f"  Dataset: {csv_output}")
    print(f"  Rows: {len(full_df)}")
    print(f"  Features: {len(ML_FEATURE_COLUMNS)}")
    print(f"  Classes: BENIGN, ATTACK")
    for label in full_df["label"].unique():
        count = (full_df["label"] == label).sum()
        print(f"    {label}: {count} ({count/len(full_df)*100:.1f}%)")
    print(f"\n  Feature mapping:")
    print(f"  {'CICIDS2017 Source':<35} → {'ML Feature'}")
    print(f"  {'─'*35}   {'─'*25}")
    feature_sources = {
        "flow_duration": "Flow Duration",
        "total_fwd_packets": "Total Fwd Packet(s)",
        "total_backward_packets": "Total Bwd Packet(s)",
        "total_bytes": "Total Fwd + Bwd Packet Length",
        "flow_bytes_s": "Flow Bytes/s",
        "flow_packets_s": "Flow Packets/s",
        "destination_port": "Dst Port",
        "source_port": "Src Port",
        "packet_length_mean": "Packet Length Mean",
        "packet_length_std": "Packet Length Std",
        "fwd_packet_length_mean": "Fwd Packet Length Mean",
        "bwd_packet_length_mean": "Bwd Packet Length Mean",
    }
    for feat in ML_FEATURE_COLUMNS:
        src = feature_sources.get(feat, "unknown")
        print(f"  {src:<35} → {feat}")

    return full_df


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python training/prepare_cicids2017.py /path/to/csvs/")
        print("")
        print("Accepts a directory of CICIDS2017 CSVs or a single CSV file.")
        print("Supports both official UNB naming and HuggingFace bvk/CICIDS-2017 naming.")
        sys.exit(1)

    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    prepare_dataset(csv_path, output_path)
