"""
SIH26145 Synthetic Training Data Generator.

Generates labeled network flow records that mimic CICIDS2017 traffic
patterns for each of the seven threat classes.

TRANSPARENCY: This is synthetic data, not the actual CICIDS2017 dataset.
The statistical distributions are derived from published CICIDS2017
research papers and documentation. A real deployment should train on
actual labeled network flow data.

The generated data is used to train a Random Forest classifier that
learnes to distinguish between traffic classes based on flow-level
features.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


# Feature columns (must match ml/features.py FEATURE_NAMES)
FEATURE_COLUMNS = [
    "flowDuration",
    "totalPackets",
    "packetsPerSecond",
    "bytesPerSecond",
    "totalBytes",
    "sourcePort",
    "destinationPort",
    "sourceEntropy",
    "destinationConcentration",
    "packetLengthMean",
    "packetLengthStd",
]

LABEL_COLUMN = "label"

# Number of samples per class (balanced dataset)
SAMPLES_PER_CLASS = 2000
RANDOM_SEED = 42


def _clip(a: np.ndarray, lo: float, hi: float) -> np.ndarray:
    """Clip array values to [lo, hi]."""
    return np.clip(a, lo, hi)


def generate_normal(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Normal traffic patterns (CICIDS2017 Benign).

    Characteristics:
    - Moderate flow duration (1-60s)
    - Low-to-moderate packet rates
    - Moderate byte rates
    - Common destination ports (80, 443, 22, 53)
    - Low source entropy (few distinct sources per flow)
    - Low-to-moderate destination concentration
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(2.0, 0.8, n), 0.1, 300.0),
        "totalPackets": _clip(rng.lognormal(5.0, 1.2, n).astype(int), 1, 50000),
        "packetsPerSecond": _clip(rng.lognormal(2.5, 1.0, n), 0.5, 2000.0),
        "bytesPerSecond": _clip(rng.lognormal(9.0, 1.5, n), 100.0, 5000000.0),
        "totalBytes": _clip(rng.lognormal(10.0, 2.0, n).astype(int), 64, 50000000),
        "sourcePort": rng.integers(1024, 65535, n),
        "destinationPort": rng.choice([80, 443, 22, 53, 8080, 3306, 5432, 8443], n),
        "sourceEntropy": _clip(rng.normal(2.0, 1.0, n), 0.0, 5.0),
        "destinationConcentration": _clip(rng.beta(2, 5, n), 0.0, 1.0),
        "packetLengthMean": _clip(rng.normal(500, 200, n), 40, 1500.0),
        "packetLengthStd": _clip(rng.normal(200, 100, n), 10, 600.0),
        "label": "Normal",
    })


def generate_ddos(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    DDoS traffic patterns (CICIDS2017 DDoS, Hulk, Slowloris, etc.).

    Characteristics:
    - Short flow duration (0.01-5s)
    - Very high packet rates (>5000 pps)
    - Very high byte rates (>5MB/s)
    - High total packets (10K-500K)
    - High source entropy (many spoofed sources)
    - High destination concentration (targeted)
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(-0.5, 0.8, n), 0.01, 10.0),
        "totalPackets": _clip(rng.lognormal(10.0, 1.0, n).astype(int), 1000, 1000000),
        "packetsPerSecond": _clip(rng.lognormal(9.0, 0.8, n), 1000, 500000.0),
        "bytesPerSecond": _clip(rng.lognormal(15.0, 1.0, n), 100000, 500000000.0),
        "totalBytes": _clip(rng.lognormal(14.0, 1.5, n).astype(int), 100000, 1000000000),
        "sourcePort": rng.integers(1024, 65535, n),
        "destinationPort": rng.choice([80, 443, 53, 8080], n),
        "sourceEntropy": _clip(rng.normal(6.5, 1.0, n), 3.0, 8.0),
        "destinationConcentration": _clip(rng.beta(8, 2, n), 0.5, 1.0),
        "packetLengthMean": _clip(rng.normal(100, 50, n), 20, 400.0),
        "packetLengthStd": _clip(rng.normal(30, 15, n), 5, 100.0),
        "label": "DDoS",
    })


def generate_c2(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    C2 beaconing patterns (periodic, low-volume).

    Characteristics:
    - Short-to-moderate flow duration (0.1-10s)
    - Low packet rates (1-50 pps)
    - Low byte rates (100-50000 B/s)
    - Few packets per flow (2-50)
    - Low source entropy (single compromised host)
    - High destination concentration (repeated C2 server)
    - Often on port 443 or non-standard ports
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(0.5, 0.7, n), 0.05, 30.0),
        "totalPackets": _clip(rng.lognormal(2.0, 0.8, n).astype(int), 2, 100),
        "packetsPerSecond": _clip(rng.lognormal(1.5, 0.8, n), 0.5, 100.0),
        "bytesPerSecond": _clip(rng.lognormal(7.5, 1.0, n), 50.0, 200000.0),
        "totalBytes": _clip(rng.lognormal(7.0, 1.2, n).astype(int), 64, 500000),
        "sourcePort": rng.integers(49000, 65535, n),
        "destinationPort": rng.choice([443, 8443, 4444, 8080, 6667], n),
        "sourceEntropy": _clip(rng.normal(1.5, 0.8, n), 0.0, 4.0),
        "destinationConcentration": _clip(rng.beta(8, 1.5, n), 0.6, 1.0),
        "packetLengthMean": _clip(rng.normal(300, 100, n), 50, 800.0),
        "packetLengthStd": _clip(rng.normal(80, 40, n), 10, 200.0),
        "label": "C2_Beaconing",
    })


def generate_dns_tunnel(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    DNS tunneling patterns (high-volume DNS).

    Characteristics:
    - Short flow duration (0.01-2s)
    - High packet rates on DNS (10-500 pps)
    - High byte rates for DNS (>5KB/s)
    - Many packets (10-200)
    - High source entropy (encoded data in queries)
    - Very high destination concentration (single DNS server)
    - Always port 53
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(-0.5, 0.6, n), 0.01, 5.0),
        "totalPackets": _clip(rng.lognormal(3.0, 0.8, n).astype(int), 5, 500),
        "packetsPerSecond": _clip(rng.lognormal(3.5, 0.7, n), 5, 1000.0),
        "bytesPerSecond": _clip(rng.lognormal(9.0, 1.0, n), 500.0, 1000000.0),
        "totalBytes": _clip(rng.lognormal(8.0, 1.0, n).astype(int), 200, 2000000),
        "sourcePort": rng.integers(1024, 65535, n),
        "destinationPort": 53,
        "sourceEntropy": _clip(rng.normal(5.5, 1.0, n), 2.0, 8.0),
        "destinationConcentration": _clip(rng.beta(10, 1, n), 0.7, 1.0),
        "packetLengthMean": _clip(rng.normal(200, 80, n), 50, 512.0),
        "packetLengthStd": _clip(rng.normal(60, 30, n), 5, 150.0),
        "label": "DGA_DNS_Tunneling",
    })


def generate_encrypted_malware(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Encrypted malware C2 patterns (high-throughput TLS).

    Characteristics:
    - Long flow duration (10-600s)
    - Moderate-to-high packet rates
    - High byte rates (>100KB/s sustained)
    - Many packets
    - High source entropy (automated tool)
    - High destination concentration
    - Port 443 or 8443
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(3.5, 0.8, n), 5.0, 1800.0),
        "totalPackets": _clip(rng.lognormal(7.0, 1.0, n).astype(int), 100, 500000),
        "packetsPerSecond": _clip(rng.lognormal(3.0, 0.8, n), 5, 5000.0),
        "bytesPerSecond": _clip(rng.lognormal(11.5, 1.0, n), 50000, 50000000.0),
        "totalBytes": _clip(rng.lognormal(13.0, 1.5, n).astype(int), 100000, 1000000000),
        "sourcePort": rng.integers(49000, 65535, n),
        "destinationPort": rng.choice([443, 8443, 993, 995], n),
        "sourceEntropy": _clip(rng.normal(6.0, 1.0, n), 3.0, 8.0),
        "destinationConcentration": _clip(rng.beta(7, 1.5, n), 0.5, 1.0),
        "packetLengthMean": _clip(rng.normal(800, 300, n), 100, 1500.0),
        "packetLengthStd": _clip(rng.normal(250, 100, n), 30, 600.0),
        "label": "Encrypted_Malware",
    })


def generate_recon(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Reconnaissance / scanning patterns.

    Characteristics:
    - Very short flow duration (0.001-1s)
    - Low packet count (1-10)
    - High packet rate (probes)
    - Low bytes per second
    - Low total bytes
    - High source entropy (scanning many ports)
    - Low destination concentration (scanning many hosts)
    - Varied destination ports
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.exponential(0.1, n), 0.001, 2.0),
        "totalPackets": _clip(rng.poisson(3, n).astype(int) + 1, 1, 30),
        "packetsPerSecond": _clip(rng.lognormal(3.0, 1.0, n), 5, 10000.0),
        "bytesPerSecond": _clip(rng.lognormal(6.0, 1.2, n), 10.0, 500000.0),
        "totalBytes": _clip(rng.lognormal(5.0, 1.0, n).astype(int), 40, 50000),
        "sourcePort": rng.integers(40000, 65535, n),
        "destinationPort": rng.integers(1, 65535, n),
        "sourceEntropy": _clip(rng.normal(5.5, 1.2, n), 2.0, 8.0),
        "destinationConcentration": _clip(rng.beta(1.5, 6, n), 0.01, 0.4),
        "packetLengthMean": _clip(rng.normal(60, 20, n), 20, 200.0),
        "packetLengthStd": _clip(rng.normal(15, 8, n), 1, 50.0),
        "label": "Reconnaissance",
    })


def generate_exfiltration(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Data exfiltration patterns (large outbound transfers).

    Characteristics:
    - Long flow duration (30-1800s)
    - High byte rates (>500KB/s)
    - Large total bytes (>10MB)
    - Moderate packet rates
    - High bytes-per-packet ratio
    - High destination concentration
    - Port 443 or other egress ports
    """
    return pd.DataFrame({
        "flowDuration": _clip(rng.lognormal(5.0, 0.8, n), 10.0, 3600.0),
        "totalPackets": _clip(rng.lognormal(8.0, 1.0, n).astype(int), 500, 1000000),
        "packetsPerSecond": _clip(rng.lognormal(3.5, 0.8, n), 5, 10000.0),
        "bytesPerSecond": _clip(rng.lognormal(13.0, 0.8, n), 100000, 100000000.0),
        "totalBytes": _clip(rng.lognormal(16.0, 1.0, n).astype(int), 1000000, 10000000000),
        "sourcePort": rng.integers(40000, 65535, n),
        "destinationPort": rng.choice([443, 8443, 993, 25, 587], n),
        "sourceEntropy": _clip(rng.normal(4.5, 1.2, n), 1.0, 8.0),
        "destinationConcentration": _clip(rng.beta(6, 2, n), 0.4, 1.0),
        "packetLengthMean": _clip(rng.normal(1000, 300, n), 200, 1500.0),
        "packetLengthStd": _clip(rng.normal(300, 100, n), 50, 600.0),
        "label": "Data_Exfiltration",
    })


def generate_dataset(
    samples_per_class: int = SAMPLES_PER_CLASS,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """
    Generate a complete labeled dataset with all 7 classes.

    Returns a DataFrame with FEATURE_COLUMNS + label column.
    """
    rng = np.random.default_rng(seed)

    generators = [
        generate_normal,
        generate_ddos,
        generate_c2,
        generate_dns_tunnel,
        generate_encrypted_malware,
        generate_recon,
        generate_exfiltration,
    ]

    dfs = [gen(samples_per_class, rng) for gen in generators]
    df = pd.concat(dfs, ignore_index=True)

    # Shuffle
    df = df.sample(frac=1.0, random_state=rng).reset_index(drop=True)

    return df


if __name__ == "__main__":
    df = generate_dataset()
    print(f"Generated {len(df)} samples across {df['label'].nunique()} classes")
    print(f"\nClass distribution:\n{df['label'].value_counts()}")
    print(f"\nFeature statistics:\n{df[FEATURE_COLUMNS].describe()}")
