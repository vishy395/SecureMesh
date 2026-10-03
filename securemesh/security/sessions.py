"""Mutually authenticated ephemeral sessions. Keys never leave memory."""
import secrets
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securemesh.config import Settings
from securemesh.protocol import (PROTOCOL_VERSION, canonical_json, decode_bytes, encode_bytes,
                                require_fields, require_int, validate_device_id)
from securemesh.security.identity import (certificate_pem, fingerprint, load_certificate,
                                         validate_device_certificate, validate_server_certificate)


class SecurityError(ValueError):
    """Fixed, sanitized event code suitable for security logging."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


@dataclass
class Session:
    session_id: str
    device_id: str
    created_at: int
    expires_at: int
    device_to_server_key: bytes = field(repr=False)
    server_to_device_key: bytes = field(repr=False)
    device_nonce_prefix: bytes = field(repr=False)
    server_nonce_prefix: bytes = field(repr=False)
    transcript_hash: str
    role: str
    max_messages: int
    send_sequence: int = 0
    receive_sequence: int = 0
    authenticated: bool = False
    lock: RLock = field(default_factory=RLock, repr=False)

    def check_live(self, now: int) -> None:
        if not self.authenticated:
            raise SecurityError("invalid_session")
        if now >= self.expires_at:
            raise SecurityError("expired_session")


def derive_material(shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Each direction has independently labeled HKDF output and nonce prefix."""
    digest = sha256(transcript)
    outputs = []
    for direction in (b"device_to_server", b"server_to_device"):
        material = HKDF(algorithm=hashes.SHA256(), length=36, salt=digest,
                        info=b"SecureMesh/v1/session/" + direction + b"/" + digest).derive(shared_secret)
        outputs.append(material)
    return outputs[0][:32], outputs[1][:32], outputs[0][32:], outputs[1][32:]


def transcript_bytes(hello: dict, response: dict) -> bytes:
    return canonical_json({"context": "SecureMesh/v1/handshake", "hello": _unsigned(hello),
                           "response": _unsigned(response)})


def _unsigned(message: dict) -> dict:
    return {key: value for key, value in message.items() if key != "signature"}


def _signature_input(label: str, content: bytes) -> bytes:
    # Role labels prevent reflection of a server signature as a device signature.
    return b"SecureMesh/v1/" + label.encode("ascii") + b"\x00" + content


def _sign(key: Ed25519PrivateKey, label: str, content: bytes) -> str:
    return encode_bytes(key.sign(_signature_input(label, content)))


def _verify(cert: x509.Certificate, signature: str, label: str, content: bytes) -> None:
    try:
        cert.public_key().verify(decode_bytes(signature, length=64), _signature_input(label, content))
    except (InvalidSignature, ValueError) as exc:
        raise SecurityError("invalid_signature") from exc


def _version(message: dict) -> None:
    if type(message.get("version")) is not int or message["version"] != PROTOCOL_VERSION:
        raise SecurityError("protocol_version_mismatch")


def _session_id(value: str) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise SecurityError("invalid_session")
    return value


HELLO_FIELDS = {"version", "type", "device_id", "server_identity", "server_fingerprint",
                "certificate", "device_fingerprint", "device_ephemeral", "device_challenge",
                "timestamp", "signature"}
RESPONSE_FIELDS = {"version", "type", "device_id", "server_identity", "server_fingerprint",
                   "certificate", "session_id", "server_ephemeral", "server_challenge",
                   "created_at", "expires_at", "challenge_expires_at", "max_messages", "signature"}
FINISH_FIELDS = {"version", "type", "device_id", "session_id", "transcript_hash", "signature"}


def _make_session(hello: dict, response: dict, ephemeral: X25519PrivateKey,
                  peer_ephemeral: str, *, role: str, authenticated: bool) -> Session:
    transcript = transcript_bytes(hello, response)
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(decode_bytes(peer_ephemeral, length=32)))
    except ValueError as exc:
        raise SecurityError("invalid_ephemeral_key") from exc
    dkey, skey, dprefix, sprefix = derive_material(shared, transcript)
    return Session(response["session_id"], hello["device_id"], response["created_at"], response["expires_at"],
                   dkey, skey, dprefix, sprefix, sha256(transcript).hex(), role,
                   response["max_messages"], authenticated=authenticated)


@dataclass
class PendingHandshake:
    hello: dict
    response: dict
    ephemeral: X25519PrivateKey = field(repr=False)
    device_certificate: x509.Certificate = field(repr=False)


class ServerHandshake:
    """Called under the control center's lock; bounded pending/challenge state."""
    def __init__(self, settings: Settings, key: Ed25519PrivateKey, certificate: x509.Certificate,
                 validate_device: Callable[[str, bytes], str], clock: Callable[[], int] = now_ms):
        self.settings, self.key, self.certificate = settings, key, certificate
        self.validate_device, self.clock = validate_device, clock
        self.pending: dict[str, PendingHandshake] = {}
        self.challenges: dict[tuple[str, str], int] = {}

    def prune(self) -> None:
        now = self.clock()
        self.pending = {sid: item for sid, item in self.pending.items()
                        if now < item.response["challenge_expires_at"]}
        self.challenges = {challenge: expiry for challenge, expiry in self.challenges.items() if now <= expiry}

    def accept_hello(self, hello: dict, topic_device: str) -> dict:
        _version(hello)
        require_fields(hello, HELLO_FIELDS)
        if hello["type"] != "hello" or hello["device_id"] != topic_device:
            raise SecurityError("identity_mismatch")
        validate_device_id(topic_device)
        if hello["server_identity"] != self.settings.server_identity or hello["server_fingerprint"] != fingerprint(self.certificate):
            raise SecurityError("server_identity_mismatch")
        pin = self.validate_device(topic_device, hello["certificate"].encode("ascii"))
        if hello["device_fingerprint"] != pin:
            raise SecurityError("invalid_certificate")
        cert = load_certificate(hello["certificate"].encode("ascii"))
        _verify(cert, hello["signature"], "device-hello", canonical_json(_unsigned(hello)))
        timestamp = require_int(hello["timestamp"])
        now = self.clock()
        if now - timestamp > self.settings.handshake_ttl_seconds * 1000 or timestamp - now > self.settings.max_clock_skew_seconds * 1000:
            raise SecurityError("expired_challenge")
        decode_bytes(hello["device_challenge"], length=32)
        decode_bytes(hello["device_ephemeral"], length=32)
        self.prune()
        challenge = (topic_device, hello["device_challenge"])
        if challenge in self.challenges:
            raise SecurityError("replayed_challenge")
        # Cache limits fail closed rather than evicting replay evidence early.
        if len(self.pending) >= self.settings.max_pending_handshakes or len(self.challenges) >= self.settings.max_pending_handshakes * 8:
            raise SecurityError("handshake_capacity")
        ephemeral = X25519PrivateKey.generate()
        response = {"version": PROTOCOL_VERSION, "type": "response", "device_id": topic_device,
                    "server_identity": self.settings.server_identity, "server_fingerprint": fingerprint(self.certificate),
                    "certificate": certificate_pem(self.certificate).decode("ascii"),
                    "session_id": secrets.token_hex(16), "server_ephemeral": encode_bytes(ephemeral.public_key().public_bytes_raw()),
                    "server_challenge": encode_bytes(secrets.token_bytes(32)), "created_at": now,
                    "expires_at": now + self.settings.session_ttl_seconds * 1000,
                    "challenge_expires_at": now + self.settings.handshake_ttl_seconds * 1000,
                    "max_messages": self.settings.max_messages_per_session}
        response["signature"] = _sign(self.key, "server-response", transcript_bytes(hello, response))
        self.pending[response["session_id"]] = PendingHandshake(dict(hello), response, ephemeral, cert)
        self.challenges[challenge] = timestamp + self.settings.handshake_ttl_seconds * 1000
        return response

    def accept_finish(self, finish: dict, topic_device: str) -> Session:
        _version(finish)
        require_fields(finish, FINISH_FIELDS)
        sid = _session_id(finish["session_id"])
        pending = self.pending.get(sid)
        if pending is None:
            raise SecurityError("invalid_session")
        if self.clock() >= pending.response["challenge_expires_at"]:
            del self.pending[sid]
            raise SecurityError("expired_challenge")
        if finish["type"] != "finish" or finish["device_id"] != topic_device or topic_device != pending.hello["device_id"]:
            raise SecurityError("identity_mismatch")
        self.validate_device(topic_device, pending.hello["certificate"].encode("ascii"))
        transcript = transcript_bytes(pending.hello, pending.response)
        if finish["transcript_hash"] != sha256(transcript).hex():
            raise SecurityError("transcript_mismatch")
        _verify(pending.device_certificate, finish["signature"], "device-finish", transcript)
        session = _make_session(pending.hello, pending.response, pending.ephemeral,
                                pending.hello["device_ephemeral"], role="server", authenticated=True)
        del self.pending[sid]
        return session


class DeviceHandshake:
    def __init__(self, settings: Settings, device_id: str, key: Ed25519PrivateKey,
                 certificate: x509.Certificate, ca_certificate: x509.Certificate,
                 trusted_server: x509.Certificate, clock: Callable[[], int] = now_ms):
        self.settings, self.device_id, self.key, self.certificate = settings, device_id, key, certificate
        self.ca_certificate, self.trusted_server, self.clock = ca_certificate, trusted_server, clock
        validate_device_certificate(certificate, ca_certificate, device_id)
        validate_server_certificate(trusted_server, ca_certificate, settings.server_identity)
        if key.public_key().public_bytes_raw() != certificate.public_key().public_bytes_raw():
            raise SecurityError("identity_key_mismatch")
        self.ephemeral: X25519PrivateKey | None = None
        self.hello: dict | None = None
        self.session: Session | None = None

    def start(self) -> dict:
        # Every attempt, including a retry, gets a new challenge and ephemeral key.
        self.ephemeral = X25519PrivateKey.generate()
        self.session = None
        self.hello = {"version": PROTOCOL_VERSION, "type": "hello", "device_id": self.device_id,
                      "server_identity": self.settings.server_identity, "server_fingerprint": fingerprint(self.trusted_server),
                      "certificate": certificate_pem(self.certificate).decode("ascii"),
                      "device_fingerprint": fingerprint(self.certificate),
                      "device_ephemeral": encode_bytes(self.ephemeral.public_key().public_bytes_raw()),
                      "device_challenge": encode_bytes(secrets.token_bytes(32)), "timestamp": self.clock()}
        self.hello["signature"] = _sign(self.key, "device-hello", canonical_json(self.hello))
        return dict(self.hello)

    def accept_response(self, response: dict) -> dict:
        if self.hello is None or self.ephemeral is None:
            raise SecurityError("invalid_session")
        _version(response)
        require_fields(response, RESPONSE_FIELDS)
        if response["type"] != "response" or response["device_id"] != self.device_id or response["server_identity"] != self.settings.server_identity:
            raise SecurityError("identity_mismatch")
        cert = load_certificate(response["certificate"].encode("ascii"))
        pin = validate_server_certificate(cert, self.ca_certificate, self.settings.server_identity,
                                          expected_fingerprint=fingerprint(self.trusted_server))
        if response["server_fingerprint"] != pin:
            raise SecurityError("invalid_certificate")
        _session_id(response["session_id"])
        decode_bytes(response["server_challenge"], length=32)
        decode_bytes(response["server_ephemeral"], length=32)
        transcript = transcript_bytes(self.hello, response)
        _verify(cert, response["signature"], "server-response", transcript)
        now = self.clock()
        created = require_int(response["created_at"])
        expiry = require_int(response["expires_at"])
        challenge_expiry = require_int(response["challenge_expires_at"])
        maximum = require_int(response["max_messages"], minimum=1, maximum=self.settings.max_messages_per_session)
        if created - now > self.settings.max_clock_skew_seconds * 1000 or now >= challenge_expiry or not created < challenge_expiry <= created + self.settings.handshake_ttl_seconds * 1000:
            raise SecurityError("expired_challenge")
        if not created < expiry <= created + self.settings.session_ttl_seconds * 1000 or now >= expiry:
            raise SecurityError("expired_session")
        self.session = _make_session(self.hello, response, self.ephemeral, response["server_ephemeral"],
                                     role="device", authenticated=False)
        self.session.max_messages = maximum
        self.ephemeral = None
        return {"version": PROTOCOL_VERSION, "type": "finish", "device_id": self.device_id,
                "session_id": self.session.session_id, "transcript_hash": self.session.transcript_hash,
                "signature": _sign(self.key, "device-finish", transcript)}
