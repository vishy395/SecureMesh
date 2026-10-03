"""Versioned wire conventions and strict JSON parsing."""
import base64
import binascii
import json
import math
import re
from enum import StrEnum
from typing import Any

PROTOCOL_VERSION = 1
TOPIC_PREFIX = "securemesh/v1/devices"
MAX_WIRE_BYTES = 65536
DIRECTION_DEVICE_TO_SERVER = "device_to_server"
DIRECTION_SERVER_TO_DEVICE = "server_to_device"


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


def handshake_topic(device_id: str, step: str) -> str:
    if step not in {"hello", "response", "finish", "ready"}:
        raise ValueError("Unknown handshake step")
    return f"{device_topic(device_id, MessageType.HANDSHAKE)}/{step}"


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Expected base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64") from exc
    if encode_bytes(decoded) != value or (length is not None and len(decoded) != length):
        raise ValueError("Noncanonical base64 or invalid length")
    return decoded


def parse_json(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_WIRE_BYTES:
        raise ValueError("Message exceeds wire size limit")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("Nonfinite JSON number")

    try:
        result = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
        if not isinstance(result, dict):
            raise ValueError("Message must be a JSON object")
        canonical_json(result)
        return result
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid JSON encoding") from exc


def require_fields(message: dict, fields: set[str]) -> None:
    if set(message) != fields:
        raise ValueError("Unexpected message fields")


def require_int(value: Any, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Invalid integer field")
    return value


def validate_telemetry(message: dict) -> dict:
    require_fields(message, {"version", "temperature", "battery", "cpu_usage", "status", "location", "timestamp"})
    if type(message["version"]) is not int or message["version"] != PROTOCOL_VERSION:
        raise ValueError("Invalid telemetry version")
    require_int(message["timestamp"])
    limits = {"temperature": (-100, 200), "battery": (0, 100), "cpu_usage": (0, 100)}
    for name, (minimum, maximum) in limits.items():
        value = message[name]
        if type(value) not in {int, float} or not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError("Invalid telemetry measurement")
    if not isinstance(message["status"], str) or message["status"] not in {"running", "idle", "warning"}:
        raise ValueError("Invalid device status")
    location = message["location"]
    if not isinstance(location, dict):
        raise ValueError("Invalid location")
    require_fields(location, {"latitude", "longitude"})
    for name, maximum in (("latitude", 90), ("longitude", 180)):
        value = location[name]
        if type(value) not in {int, float} or not math.isfinite(value) or not -maximum <= value <= maximum:
            raise ValueError("Invalid location")
    return message


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
