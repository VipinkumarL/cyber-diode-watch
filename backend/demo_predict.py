"""Safe metadata-only demo client for POST /api/predict.

This script sends synthetic network-flow metadata to a local backend. It does
not generate packets, open sockets to targets, scan hosts, or replay traffic.
"""

from __future__ import annotations

import argparse
import json
import time
from copy import deepcopy
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REQUIRED_RESPONSE_FIELDS = {
    "alert",
    "updatedFlow",
    "detectionTimeMs",
}

REQUIRED_ALERT_FIELDS = {
    "threatClass",
    "confidence",
    "severity",
    "detector",
    "supportingEvidence",
}


def _base_flow(flow_id: str, scenario: str) -> dict[str, Any]:
    return {
        "flowId": flow_id,
        "timestamp": int(time.time() * 1000),
        "sourceIp": "10.10.1.25",
        "destinationIp": "93.184.216.34",
        "protocol": "TCP",
        "sourcePort": 52144,
        "destinationPort": 443,
        "flowDuration": 12.4,
        "totalPackets": 96,
        "packetsPerSecond": 7.74,
        "bytesPerSecond": 38240.0,
        "totalBytes": 474176,
        "classification": "Normal",
        "confidence": 0.0,
        "severity": "INFO",
        "sourceEntropy": 2.1,
        "destinationConcentration": 0.18,
        "packetLengthMean": 512.0,
        "packetLengthStd": 84.5,
        "isSuspicious": False,
        "scenario": scenario,
    }


def demo_flows() -> dict[str, dict[str, Any]]:
    flows = {
        "normal": _base_flow("DEMO-NORMAL-001", "normal"),
        "ddos": _base_flow("DEMO-DDOS-001", "ddos"),
        "recon": _base_flow("DEMO-RECON-001", "recon"),
        "c2": _base_flow("DEMO-C2-001", "c2"),
        "dns": _base_flow("DEMO-DNS-001", "dns"),
        "encrypted_malware": _base_flow("DEMO-ENC-001", "encrypted_malware"),
        "exfil": _base_flow("DEMO-EXFIL-001", "exfil"),
    }

    flows["ddos"].update(
        {
            "protocol": "UDP",
            "sourcePort": 49152,
            "destinationIp": "10.10.8.20",
            "destinationPort": 443,
            "flowDuration": 0.35,
            "totalPackets": 52000,
            "packetsPerSecond": 148571.43,
            "bytesPerSecond": 11800000.0,
            "totalBytes": 4130000,
            "sourceEntropy": 7.2,
            "destinationConcentration": 0.94,
            "packetLengthMean": 79.4,
            "packetLengthStd": 18.6,
        }
    )
    flows["recon"].update(
        {
            "destinationIp": "10.10.20.45",
            "destinationPort": 22,
            "flowDuration": 0.02,
            "totalPackets": 3,
            "packetsPerSecond": 150.0,
            "bytesPerSecond": 420.0,
            "totalBytes": 126,
            "sourceEntropy": 5.4,
            "destinationConcentration": 0.05,
            "packetLengthMean": 42.0,
            "packetLengthStd": 4.0,
        }
    )
    flows["c2"].update(
        {
            "destinationIp": "198.51.100.24",
            "destinationPort": 8443,
            "flowDuration": 1.2,
            "totalPackets": 12,
            "packetsPerSecond": 10.0,
            "bytesPerSecond": 2400.0,
            "totalBytes": 2880,
            "sourceEntropy": 1.4,
            "destinationConcentration": 0.91,
            "packetLengthMean": 240.0,
            "packetLengthStd": 11.0,
        }
    )
    flows["dns"].update(
        {
            "protocol": "UDP",
            "destinationIp": "8.8.8.8",
            "destinationPort": 53,
            "flowDuration": 0.8,
            "totalPackets": 72,
            "packetsPerSecond": 90.0,
            "bytesPerSecond": 22000.0,
            "totalBytes": 17600,
            "sourceEntropy": 5.8,
            "destinationConcentration": 0.96,
            "packetLengthMean": 244.0,
            "packetLengthStd": 35.0,
        }
    )
    flows["encrypted_malware"].update(
        {
            "destinationIp": "203.0.113.77",
            "destinationPort": 8443,
            "flowDuration": 340.0,
            "totalPackets": 4200,
            "packetsPerSecond": 230.0,
            "bytesPerSecond": 6200000.0,
            "totalBytes": 210800000,
            "sourceEntropy": 5.6,
            "destinationConcentration": 0.89,
            "packetLengthMean": 1260.0,
            "packetLengthStd": 210.0,
        }
    )
    flows["exfil"].update(
        {
            "destinationIp": "203.0.113.90",
            "destinationPort": 443,
            "flowDuration": 420.0,
            "totalPackets": 18000,
            "packetsPerSecond": 42.86,
            "bytesPerSecond": 7800000.0,
            "totalBytes": 3276000000,
            "sourceEntropy": 5.2,
            "destinationConcentration": 0.93,
            "packetLengthMean": 182000.0,
            "packetLengthStd": 1500.0,
        }
    )

    return {name: deepcopy(flow) for name, flow in flows.items()}


def post_predict(base_url: str, flow: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps({"flow": flow}).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}/api/predict",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_response(data: dict[str, Any]) -> None:
    missing = REQUIRED_RESPONSE_FIELDS - data.keys()
    if missing:
        raise AssertionError(f"Missing response fields: {sorted(missing)}")
    if not isinstance(data["detectionTimeMs"], int):
        raise AssertionError("detectionTimeMs must be an integer")
    if not isinstance(data["updatedFlow"], dict):
        raise AssertionError("updatedFlow must be an object")
    alert = data["alert"]
    if not isinstance(alert, dict):
        raise AssertionError("alert must be an object")
    missing_alert = REQUIRED_ALERT_FIELDS - alert.keys()
    if missing_alert:
        raise AssertionError(f"Missing alert fields: {sorted(missing_alert)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--scenario",
        choices=[*demo_flows().keys(), "all"],
        default="normal",
    )
    args = parser.parse_args()

    scenarios = demo_flows()
    selected = scenarios if args.scenario == "all" else {args.scenario: scenarios[args.scenario]}

    try:
        for name, flow in selected.items():
            data = post_predict(args.base_url, flow)
            verify_response(data)
            alert = data["alert"]
            print(
                f"{name}: {alert['threatClass']} "
                f"{alert['confidence']:.2f} {alert['severity']} "
                f"via {alert['detector']} in {data['detectionTimeMs']}ms"
            )
    except (HTTPError, URLError, TimeoutError, AssertionError) as exc:
        print(f"Demo failed: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
