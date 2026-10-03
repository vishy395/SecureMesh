"""Versioned wire conventions; encrypted messages arrive in Stage 2."""
import json
import re
from enum import StrEnum
from typing import Any

PROTOCOL_VERSION = 1
TOPIC_PREFIX = "securemesh/v1/devices"


class MessageType(StrEnum):
    HANDSHAKE = "handshake"
    TELEMETRY = "telemetry"
    COMMAND = "commands"
    ACK = "acks"


def validate_device_id(device_id: str) -> str:
    # Restrict IDs so filesystem paths and MQTT topics cannot be injected.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", device_id):
        raise ValueError("Device ID must be 1-64 ASCII letters, digits, underscores or hyphens")
    return device_id


def device_topic(device_id: str, message_type: MessageType) -> str:
    return f"{TOPIC_PREFIX}/{validate_device_id(device_id)}/{message_type.value}"


def canonical_json(message: dict[str, Any]) -> bytes:
    """SecureMesh JSON encoding: UTF-8, sorted keys, no whitespace or NaN.

    This is a Python protocol convention, not a claim of RFC 8785 support.
    """
    def check(value: Any) -> None:
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("Protocol JSON object keys must be strings")
            for item in value.values():
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError("Unsupported protocol JSON value")

    if not isinstance(message, dict):
        raise ValueError("Protocol message must be an object")
    check(message)
    return json.dumps(message, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")
