"""Certificate admission and registry policy; repository handles persistence."""
import logging
import re
from threading import RLock
from typing import Callable

from cryptography import x509

from securemesh.security.identity import IdentityError, load_certificate, validate_device_certificate
from securemesh.server.repository import DeviceRepository, RegistryError
from securemesh.config import Settings
from securemesh.protocol import (TOPIC_PREFIX, canonical_json, handshake_topic,
                                 parse_json, validate_device_id, validate_telemetry)
from securemesh.security.envelopes import decrypt_message, encrypt_message
from securemesh.security.sessions import SecurityError, ServerHandshake, Session, now_ms
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger("securemesh.registry")


class DeviceService:
    def __init__(self, repository: DeviceRepository, ca_certificate: x509.Certificate):
        self.repository = repository
        self.ca_certificate = ca_certificate

    def register_device(self, device_id: str, certificate: bytes) -> dict:
        try:
            cert = load_certificate(certificate)
            pin = validate_device_certificate(cert, self.ca_certificate, device_id)
            device = self.repository.register_device(device_id, pin, certificate.decode("ascii"))
        except (IdentityError, RegistryError):
            logger.warning("device_registration_rejected")
            raise
        logger.info("device_registered", extra={"device_id": device_id})
        return device

    def validate_registered_device(self, device_id: str, certificate: bytes) -> str:
        try:
            device = self.repository.get_device(device_id)
            if device is None:
                raise IdentityError("Unknown device")
            if device["revoked_at"] is not None or device["status"] == "revoked":
                raise IdentityError("Device is revoked")
            return validate_device_certificate(load_certificate(certificate), self.ca_certificate,
                                               device_id, expected_fingerprint=device["certificate_fingerprint"])
        except IdentityError:
            logger.warning("device_identity_rejected")
            raise

    def list_devices(self) -> list[dict]:
        # Public registry metadata only; certificate PEM stays in local storage.
        return [{k: v for k, v in device.items() if k != "certificate"}
                for device in self.repository.list_devices()]

    def revoke_device(self, device_id: str) -> None:
        self.repository.revoke_device(device_id)
        logger.info("device_revoked", extra={"device_id": device_id})


class TelemetryService:
    """Application-level admission independent of MQTT broker authentication."""
    def __init__(self, settings: Settings, registry: DeviceService, server_key: Ed25519PrivateKey,
                 server_certificate: x509.Certificate, clock: Callable[[], int] = now_ms):
        self.settings, self.registry, self.repository, self.clock = settings, registry, registry.repository, clock
        self.lock = RLock()
        self.sessions: dict[str, Session] = {}
        self.handshake = ServerHandshake(settings, server_key, server_certificate, self._validate_device, clock)
        # Keys are not recoverable from metadata, so old rows can never be resumed.
        self.repository.invalidate_sessions()

    def _validate_device(self, device_id: str, certificate: bytes) -> str:
        record = self.repository.get_device(device_id)
        if record is None:
            raise SecurityError("unknown_device")
        if record["revoked_at"] is not None or record["status"] == "revoked":
            raise SecurityError("revoked_device")
        try:
            return self.registry.validate_registered_device(device_id, certificate)
        except IdentityError as exc:
            raise SecurityError("invalid_certificate") from exc

    def _event(self, code: str, device_id: str | None = None, session_id: str | None = None) -> None:
        self.repository.record_event(code, device_id, session_id)
        logger.warning(code, extra={"device_id": device_id, "session_id": session_id})

    def prune(self) -> None:
        with self.lock:
            self.handshake.prune()
            for sid, session in list(self.sessions.items()):
                if self.clock() >= session.expires_at:
                    self.repository.invalidate_sessions(sid)
                    session.authenticated = False
                    del self.sessions[sid]

    def process_message(self, topic: str, payload: bytes, *, retained: bool = False) -> tuple[str, bytes] | None:
        """Return an optional handshake reply; reject with sanitized persistent events."""
        device_id = None
        session_id = None
        is_handshake = False
        with self.lock:
            try:
                prefix = TOPIC_PREFIX + "/"
                if not topic.startswith(prefix):
                    raise SecurityError("invalid_topic")
                parts = topic[len(prefix):].split("/")
                validate_device_id(parts[0])
                device_id = parts[0]
                is_handshake = len(parts) == 3 and parts[1] == "handshake"
                if retained:
                    raise SecurityError("retained_message_rejected")
                message = parse_json(payload)
                candidate = message.get("session_id")
                if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{32}", candidate):
                    session_id = candidate
                if is_handshake and parts[2] == "hello":
                    response = self.handshake.accept_hello(message, device_id)
                    return handshake_topic(device_id, "response"), canonical_json(response)
                if is_handshake and parts[2] == "finish":
                    session = self.handshake.accept_finish(message, device_id)
                    ready = encrypt_message(session, {"session_id": session.session_id,
                        "transcript_hash": session.transcript_hash, "status": "ready"}, "handshake_ready", now=self.clock())
                    self.repository.create_session(session)
                    for sid, previous in list(self.sessions.items()):
                        if previous.device_id == device_id:
                            previous.authenticated = False
                            del self.sessions[sid]
                    self.sessions[session.session_id] = session
                    self.repository.record_event("session_authenticated", device_id, session.session_id)
                    logger.info("session_authenticated", extra={"device_id": device_id, "session_id": session.session_id})
                    return handshake_topic(device_id, "ready"), canonical_json(ready)
                if parts == [device_id, "telemetry"]:
                    self.accept_telemetry(device_id, message)
                    return None
                raise SecurityError("invalid_topic")
            except SecurityError as exc:
                self._event(exc.code, device_id, session_id)
                if is_handshake:
                    self._event("handshake_failure", device_id, session_id)
            except IdentityError:
                self._event("invalid_certificate", device_id, session_id)
                if is_handshake:
                    self._event("handshake_failure", device_id, session_id)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                self._event("invalid_message", device_id, session_id)
                if is_handshake:
                    self._event("handshake_failure", device_id, session_id)
            return None

    def accept_telemetry(self, device_id: str, envelope: dict) -> None:
        with self.lock:
            device = self.repository.get_device(device_id)
            if device is None:
                raise SecurityError("unknown_device")
            if device["revoked_at"] is not None or device["status"] == "revoked":
                raise SecurityError("revoked_device")
            sid = envelope.get("session_id")
            if not isinstance(sid, str) or sid not in self.sessions:
                raise SecurityError("invalid_session")
            session = self.sessions[sid]
            if session.device_id != device_id:
                raise SecurityError("identity_mismatch")
            now = self.clock()
            with session.lock:
                payload = decrypt_message(session, envelope, "telemetry", now=now)
                try:
                    validate_telemetry(payload)
                except ValueError as exc:
                    raise SecurityError("invalid_telemetry") from exc
                age = now - payload["timestamp"]
                if age > self.settings.telemetry_max_age_seconds * 1000 or age < -self.settings.max_clock_skew_seconds * 1000:
                    raise SecurityError("stale_message")
                try:
                    self.repository.store_telemetry(sid, device_id, envelope["sequence"], payload, now)
                except RegistryError as exc:
                    raise SecurityError("session_state_conflict") from exc
                # Advance memory only after the database transaction commits.
                session.receive_sequence = envelope["sequence"]
                logger.info("telemetry_accepted", extra={"device_id": device_id, "session_id": sid,
                                                        "sequence": envelope["sequence"]})

    def shutdown(self) -> None:
        with self.lock:
            self.repository.invalidate_sessions()
            for session in self.sessions.values():
                session.authenticated = False
            self.sessions.clear()
            self.handshake.pending.clear()
            self.handshake.challenges.clear()
