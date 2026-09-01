"""
SIH26145 ML Module — Machine Learning Threat Classification.

Provides trained Random Forest model for network-flow classification.

Supports two model types:
  1. CICIDS2017 binary classifier (BENIGN vs ATTACK) — real labeled data
  2. Synthetic multi-class classifier — fallback training data

Model priority: CICIDS2017 > synthetic
"""
