"""AES-256-GCM envelopes. Authentication never mutates receive replay state."""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securemesh.protocol import (DIRECTION_DEVICE_TO_SERVER, DIRECTION_SERVER_TO_DEVICE,
    PROTOCOL_VERSION, canonical_json, decode_bytes, encode_bytes, parse_json, require_fields, require_int)
from securemesh.security.sessions import SecurityError, Session, now_ms

HEADER_FIELDS = {"version", "message_type", "device_id", "session_id", "sequence", "direction"}
ENVELOPE_FIELDS = HEADER_FIELDS | {"nonce", "ciphertext"}


def nonce_for_sequence(prefix: bytes, sequence: int) -> bytes:
    require_int(sequence, minimum=1, maximum=2**64 - 1)
    if len(prefix) != 4:
        raise ValueError("Nonce prefix must be 4 bytes")
    return prefix + sequence.to_bytes(8, "big")


def _material(session: Session, direction: str) -> tuple[bytes, bytes]:
    if direction == DIRECTION_DEVICE_TO_SERVER:
        return session.device_to_server_key, session.device_nonce_prefix
    if direction == DIRECTION_SERVER_TO_DEVICE:
        return session.server_to_device_key, session.server_nonce_prefix
    raise SecurityError("wrong_direction")


def encrypt_message(session: Session, plaintext: dict, message_type: str,
                    *, now: int | None = None) -> dict:
    """Reserve/burn a counter before encryption, even if later publish fails."""
    now = now_ms() if now is None else now
    with session.lock:
        session.check_live(now)
        if session.send_sequence >= session.max_messages:
            raise SecurityError("session_message_limit")
        session.send_sequence += 1
        sequence = session.send_sequence
        direction = DIRECTION_DEVICE_TO_SERVER if session.role == "device" else DIRECTION_SERVER_TO_DEVICE
        key, prefix = _material(session, direction)
        header = {"version": PROTOCOL_VERSION, "message_type": message_type, "device_id": session.device_id,
                  "session_id": session.session_id, "sequence": sequence, "direction": direction}
        nonce = nonce_for_sequence(prefix, sequence)
        ciphertext = AESGCM(key).encrypt(nonce, canonical_json(plaintext), canonical_json(header))
        return {**header, "nonce": encode_bytes(nonce), "ciphertext": encode_bytes(ciphertext)}


def decrypt_message(session: Session, envelope: dict, message_type: str,
                    *, now: int | None = None, allow_pending: bool = False) -> dict:
    """Caller commits sequence after authentication, payload validation and storage."""
    now = now_ms() if now is None else now
    if allow_pending:
        if now >= session.expires_at:
            raise SecurityError("expired_session")
    else:
        session.check_live(now)
    require_fields(envelope, ENVELOPE_FIELDS)
    if type(envelope["version"]) is not int or envelope["version"] != PROTOCOL_VERSION:
        raise SecurityError("protocol_version_mismatch")
    if envelope["device_id"] != session.device_id or envelope["session_id"] != session.session_id:
        raise SecurityError("invalid_session")
    direction = DIRECTION_SERVER_TO_DEVICE if session.role == "device" else DIRECTION_DEVICE_TO_SERVER
    if envelope["direction"] != direction:
        raise SecurityError("wrong_direction")
    if envelope["message_type"] != message_type:
        raise SecurityError("invalid_message_type")
    try:
        sequence = require_int(envelope["sequence"], minimum=1, maximum=session.max_messages)
    except ValueError as exc:
        raise SecurityError("invalid_sequence") from exc
    key, prefix = _material(session, direction)
    nonce = decode_bytes(envelope["nonce"], length=12)
    if nonce != nonce_for_sequence(prefix, sequence):
        raise SecurityError("invalid_nonce")
    header = {name: envelope[name] for name in HEADER_FIELDS}
    try:
        plaintext = AESGCM(key).decrypt(nonce, decode_bytes(envelope["ciphertext"]), canonical_json(header))
    except InvalidTag as exc:
        raise SecurityError("invalid_authentication_tag") from exc
    if sequence <= session.receive_sequence:
        raise SecurityError("replay_attempt")
    return parse_json(plaintext)


def accept_ready(session: Session, envelope: dict, *, now: int | None = None) -> None:
    with session.lock:
        payload = decrypt_message(session, envelope, "handshake_ready", now=now, allow_pending=True)
        if payload != {"session_id": session.session_id, "transcript_hash": session.transcript_hash, "status": "ready"}:
            raise SecurityError("transcript_mismatch")
        session.receive_sequence = envelope["sequence"]
        session.authenticated = True
