"""Synthetic readings; no physical hardware dependencies."""
import random

from securemesh.protocol import PROTOCOL_VERSION
from securemesh.security.sessions import now_ms


def generate_telemetry() -> dict:
    return {"version": PROTOCOL_VERSION, "temperature": round(random.uniform(20, 35), 2),
            "battery": round(random.uniform(50, 100), 2), "cpu_usage": round(random.uniform(1, 90), 2),
            "status": "running", "location": {"latitude": 12.9716, "longitude": 77.5946},
            "timestamp": now_ms()}
