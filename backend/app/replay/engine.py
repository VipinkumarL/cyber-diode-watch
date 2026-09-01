"""
SIH26145 Replay Engine.

Generates safe synthetic flow records for demonstration.
Generates ONLY recorded/synthetic data — never real attack traffic.

The engine produces flows matching the same generators used in the
frontend (src/lib/detection.ts) so results are comparable.
"""

from __future__ import annotations

import random
import time
from typing import Callable, Optional

from ..models.schemas import NetworkFlow, ThreatClass, Severity


# ── Synthetic Flow Generators ─────────────────────────────────────

_flow_counter = 0


def _random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _internal_ip() -> str:
    return f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}"


def generate_normal_flow() -> NetworkFlow:
    """Generate a benign network flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_random_ip(),
        destinationIp=_internal_ip(),
        protocol=random.choice(["TCP", "UDP", "ICMP"]),
        sourcePort=random.randint(1024, 61024),
        destinationPort=random.choice([80, 443, 8080, 22, 53]),
        flowDuration=round(random.uniform(0.1, 30.0), 3),
        totalPackets=random.randint(10, 500),
        packetsPerSecond=round(random.uniform(1, 100), 2),
        bytesPerSecond=round(random.uniform(100, 50000), 2),
        totalBytes=random.randint(1000, 500000),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(1, 5), 2),
        destinationConcentration=round(random.uniform(0, 0.3), 2),
        packetLengthMean=round(random.uniform(100, 1000), 1),
        packetLengthStd=round(random.uniform(50, 200), 1),
        isSuspicious=False,
        scenario="normal",
    )


def generate_ddos_flow() -> NetworkFlow:
    """Generate a synthetic DDoS-like flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    pps = random.randint(5000, 20000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_random_ip(),
        destinationIp=f"10.0.1.{random.randint(1, 10)}",
        protocol="UDP",
        sourcePort=random.randint(1024, 61024),
        destinationPort=random.choice([80, 443, 53, 8080]),
        flowDuration=round(random.uniform(0.01, 2.0), 3),
        totalPackets=random.randint(10000, 200000),
        packetsPerSecond=float(pps),
        bytesPerSecond=round(pps * random.uniform(50, 550), 2),
        totalBytes=random.randint(1000000, 100000000),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(5, 8), 2),
        destinationConcentration=round(random.uniform(0.6, 1.0), 2),
        packetLengthMean=round(random.uniform(50, 250), 1),
        packetLengthStd=round(random.uniform(10, 60), 1),
        isSuspicious=False,
        scenario="ddos",
    )


def generate_c2_flow() -> NetworkFlow:
    """Generate a synthetic C2 beaconing flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_random_ip(),
        destinationIp=f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        protocol="TCP",
        sourcePort=random.randint(49000, 50000),
        destinationPort=443,
        flowDuration=round(random.uniform(0.05, 0.5), 3),
        totalPackets=random.randint(4, 24),
        packetsPerSecond=round(random.uniform(5, 35), 2),
        bytesPerSecond=round(random.uniform(100, 5000), 2),
        totalBytes=random.randint(500, 10000),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(1, 3), 2),
        destinationConcentration=round(random.uniform(0.01, 0.2), 2),
        packetLengthMean=round(random.uniform(100, 500), 1),
        packetLengthStd=round(random.uniform(10, 50), 1),
        isSuspicious=False,
        scenario="c2",
    )


def generate_dns_flow() -> NetworkFlow:
    """Generate a synthetic DNS tunneling flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_random_ip(),
        destinationIp="8.8.8.8",
        protocol="UDP",
        sourcePort=random.randint(1024, 61024),
        destinationPort=53,
        flowDuration=round(random.uniform(0.01, 0.5), 3),
        totalPackets=random.randint(2, 12),
        packetsPerSecond=round(random.uniform(5, 55), 2),
        bytesPerSecond=round(random.uniform(100, 2000), 2),
        totalBytes=random.randint(200, 5000),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(2, 5), 2),
        destinationConcentration=0.95,
        packetLengthMean=round(random.uniform(50, 200), 1),
        packetLengthStd=round(random.uniform(5, 30), 1),
        isSuspicious=False,
        scenario="dns",
    )


def generate_recon_flow() -> NetworkFlow:
    """Generate a synthetic reconnaissance/scanning flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_random_ip(),
        destinationIp=f"10.0.{random.randint(0, 9)}.{random.randint(1, 254)}",
        protocol="TCP",
        sourcePort=random.randint(40000, 41000),
        destinationPort=random.randint(1, 1000),
        flowDuration=round(random.uniform(0.001, 0.1), 4),
        totalPackets=random.randint(1, 6),
        packetsPerSecond=round(random.uniform(10, 110), 2),
        bytesPerSecond=round(random.uniform(10, 1000), 2),
        totalBytes=random.randint(40, 500),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(4, 6), 2),
        destinationConcentration=round(random.uniform(0.01, 0.1), 2),
        packetLengthMean=round(random.uniform(40, 90), 1),
        packetLengthStd=round(random.uniform(1, 11), 1),
        isSuspicious=False,
        scenario="recon",
    )


def generate_exfil_flow() -> NetworkFlow:
    """Generate a synthetic data exfiltration flow."""
    global _flow_counter
    _flow_counter += 1
    now_ms = int(time.time() * 1000)
    bps = random.uniform(50000, 550000)
    return NetworkFlow(
        flowId=f"FLOW-{_flow_counter:07d}",
        timestamp=now_ms,
        sourceIp=_internal_ip(),
        destinationIp=_random_ip(),
        protocol="TCP",
        sourcePort=random.randint(40000, 41000),
        destinationPort=random.choice([443, 8443, 993, 25]),
        flowDuration=round(random.uniform(10, 60), 3),
        totalPackets=random.randint(5000, 100000),
        packetsPerSecond=round(random.uniform(100, 2000), 2),
        bytesPerSecond=round(bps, 2),
        totalBytes=int(bps * 30),
        classification=ThreatClass.Normal,
        confidence=0.0,
        severity=Severity.INFO,
        sourceEntropy=round(random.uniform(1, 3), 2),
        destinationConcentration=round(random.uniform(0.01, 0.1), 2),
        packetLengthMean=round(random.uniform(500, 1500), 1),
        packetLengthStd=round(random.uniform(50, 250), 1),
        isSuspicious=False,
        scenario="exfil",
    )


# ── Generator Registry ────────────────────────────────────────────

_GENERATORS: dict[str, Callable[[], NetworkFlow]] = {
    "normal": generate_normal_flow,
    "ddos": generate_ddos_flow,
    "c2": generate_c2_flow,
    "dns": generate_dns_flow,
    "recon": generate_recon_flow,
    "exfil": generate_exfil_flow,
}


def get_generator(scenario: str) -> Callable[[], NetworkFlow]:
    """Return the flow generator for a given scenario."""
    return _GENERATORS.get(scenario, generate_normal_flow)


def reset_flow_counter() -> None:
    """Reset the flow counter (for replay reset)."""
    global _flow_counter
    _flow_counter = 0
