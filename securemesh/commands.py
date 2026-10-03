"""Strict command policy shared by the API and simulated devices."""
import math
import re

from securemesh.protocol import PROTOCOL_VERSION, require_fields, require_int
from securemesh.security.sessions import SecurityError, Session

COMMAND_FIELDS = {
    "version", "command_id", "target_device_id", "command_type", "parameters",
    "issued_at", "expires_at", "session_id", "sequence",
}
CONFIG_FIELDS = {"telemetry_interval", "location_enabled"}


def validate_parameters(kind: str, parameters: dict) -> dict:
    """Authorize a supported operation and its exact parameter schema."""
    if not isinstance(parameters, dict):
        raise SecurityError("invalid_parameters")
    if kind in {"START", "STOP", "RESTART"}:
        valid = not parameters
    elif kind == "CHANGE_THRESHOLD":
        value = parameters.get("threshold")
        valid = (
            set(parameters) == {"threshold"}
            and type(value) in {int, float}
            and -100 <= value <= 200
            and math.isfinite(value)
        )
    elif kind == "UPDATE_CONFIG":
        valid = bool(parameters) and set(parameters) <= CONFIG_FIELDS
        for key, value in parameters.items():
            if key == "telemetry_interval":
                valid = valid and (
                    type(value) in {int, float}
                    and 0.1 <= value <= 3600
                    and math.isfinite(value)
                )
            elif key == "location_enabled":
                valid = valid and type(value) is bool
    else:
        raise SecurityError("unsupported_command")
    if not valid:
        raise SecurityError("invalid_parameters")
    return parameters


def validate_command_id(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{32}", value):
        raise SecurityError("invalid_command_id")


def validate_command(
    payload: dict, envelope: dict, session: Session, now: int,
    skew: int = 5000, max_age: int = 30000,
) -> None:
    require_fields(payload, COMMAND_FIELDS)
    if type(payload["version"]) is not int or payload["version"] != PROTOCOL_VERSION:
        raise SecurityError("protocol_version_mismatch")
    if payload["target_device_id"] != session.device_id:
        raise SecurityError("wrong_target_device")
    if payload["session_id"] != session.session_id:
        raise SecurityError("invalid_session")
    if require_int(payload["sequence"], minimum=1) != envelope["sequence"]:
        raise SecurityError("invalid_sequence")
    validate_command_id(payload["command_id"])
    issued = require_int(payload["issued_at"])
    expires = require_int(payload["expires_at"])
    if now >= expires or not issued < expires <= session.expires_at:
        raise SecurityError("expired_command")
    if now - issued > max_age or issued - now > skew:
        raise SecurityError("stale_message")
    validate_parameters(payload["command_type"], payload["parameters"])
