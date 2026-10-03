"""Certificate admission and registry policy; repository handles persistence."""
import logging
import re
import secrets
from securemesh.commands import validate_parameters, validate_command_id
from securemesh.protocol import MessageType, device_topic, require_fields, require_int
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
        return [{**{k: v for k, v in device.items() if k != "certificate"},
                 "state": "REVOKED" if device["revoked_at"] or device["status"] == "revoked" else "ACTIVE"}
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
            self.repository.expire_commands(self.clock())
            for sid, session in list(self.sessions.items()):
                record = self.repository.get_session(sid)
                if self.clock() >= session.expires_at:
                    self.repository.record_event('session_rotation',session.device_id,sid)
                    self.invalidate_session(sid)
                elif record is None or not record['active']:
                    self.invalidate_session(sid)

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
                            self.repository.record_event("session_rotation", device_id, sid)
                            self.repository.record_event("session_invalidation", device_id, sid)
                            previous.authenticated = False
                            del self.sessions[sid]
                    self.sessions[session.session_id] = session
                    self.repository.record_event("session_authenticated", device_id, session.session_id)
                    logger.info("session_authenticated", extra={"device_id": device_id, "session_id": session.session_id})
                    return handshake_topic(device_id, "ready"), canonical_json(ready)
                if parts == [device_id, "acks"]:
                    self.accept_ack(device_id, message)
                    return None
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
            record = self.repository.get_session(sid)
            if record is None or not record['active']:
                raise SecurityError('invalid_session')
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

    def active_session(self, device_id):
        device = self.repository.get_device(device_id)
        if device is None: raise SecurityError('unknown_device')
        if device['revoked_at'] or device['status']=='revoked':
            raise SecurityError('revoked_device')
        for session in self.sessions.values():
            if session.device_id == device_id:
                session.check_live(self.clock())
                record = self.repository.get_session(session.session_id)
                if record is None or not record['active']: raise SecurityError('invalid_session')
                return session
        raise SecurityError('invalid_session')

    def send_command(self, device_id, command_type, parameters, publish):
        with self.lock:
            try:
                validate_parameters(command_type, parameters)
                session = self.active_session(device_id)
                with session.lock:
                    now = self.clock()
                    payload = {'version':1, 'command_id':secrets.token_hex(16),
                        'target_device_id':device_id, 'command_type':command_type,
                        'parameters':parameters, 'issued_at':now,
                        'expires_at':min(now+30000,session.expires_at),
                        'session_id':session.session_id, 'sequence':session.send_sequence+1}
                    envelope = encrypt_message(session, payload, 'command', now=now)
                    try:
                        self.repository.create_command(payload)
                    except RegistryError as exc:
                        raise SecurityError('session_state_conflict') from exc
                    self.repository.record_event('command_created',device_id,session.session_id)
                    try:
                        publish(device_topic(device_id,MessageType.COMMAND),canonical_json(envelope))
                    except (ConnectionError,RuntimeError,OSError):
                        self.repository.command_status(payload['command_id'],'FAILED')
                        raise SecurityError('command_publish_failed')
                    self.repository.command_status(payload['command_id'],'SENT')
                    self.repository.record_event('command_sent',device_id,session.session_id)
                    return self.repository.get_command(payload['command_id'])
            except SecurityError as exc:
                self._event('revoked_device_command_attempt' if exc.code=='revoked_device' else exc.code,device_id)
                raise

    def accept_ack(self, device_id, envelope):
        with self.lock:
            session = self.active_session(device_id)
            if envelope.get('session_id') != session.session_id: raise SecurityError('invalid_session')
            with session.lock:
                now = self.clock()
                payload = decrypt_message(session,envelope,'ack',now=now)
                require_fields(payload,{'version','command_id','device_id','status','timestamp','command_sequence'})
                if type(payload['version']) is not int or payload['version']!=1: raise SecurityError('protocol_version_mismatch')
                if payload['device_id']!=device_id: raise SecurityError('wrong_target_device')
                validate_command_id(payload['command_id'])
                if payload['status'] not in {'EXECUTED','ALREADY_PROCESSED','REJECTED','FAILED'}: raise SecurityError('invalid_ack')
                timestamp = require_int(payload['timestamp'])
                if now-timestamp>30000 or timestamp-now>self.settings.max_clock_skew_seconds*1000: raise SecurityError('stale_message')
                command = self.repository.get_command(payload['command_id'])
                if command is None or command['device_id']!=device_id or command['session_id']!=session.session_id or require_int(payload['command_sequence'],minimum=1)!=command['sequence']:
                    raise SecurityError('invalid_ack')
                if payload['status'] in {'EXECUTED','ALREADY_PROCESSED'} and not command['issued_at'] <= timestamp < command['expires_at']:
                    raise SecurityError('expired_command')
                try:
                    self.repository.store_ack(session,envelope,payload,now)
                except RegistryError as exc:
                    raise SecurityError('session_state_conflict') from exc
                session.receive_sequence=envelope['sequence']
                event = {'EXECUTED':'command_executed','ALREADY_PROCESSED':'duplicate_command','REJECTED':'command_rejected','FAILED':'command_failed'}[payload['status']]
                self.repository.record_event(event,device_id,session.session_id)

    def invalidate_session(self, session_id):
        with self.lock:
            session = self.sessions.pop(session_id,None)
            record = self.repository.get_session(session_id)
            self.repository.invalidate_sessions(session_id)
            if session:
                session.authenticated=False
                if record and record['active']:
                    self.repository.record_event('session_invalidation',session.device_id,session_id)

    def invalidate_device_sessions(self, device_id):
        with self.lock:
            for sid, session in list(self.sessions.items()):
                if session.device_id==device_id: self.invalidate_session(sid)
            self.repository.invalidate_device_sessions(device_id)
            self.handshake.pending = {sid:item for sid,item in self.handshake.pending.items() if item.hello['device_id']!=device_id}

    def revoke_device(self, device_id):
        with self.lock:
            self.registry.revoke_device(device_id)
            self.invalidate_device_sessions(device_id)

    def rotate_session(self, device_id, publish):
        with self.lock:
            session = self.active_session(device_id)
            with session.lock:
                envelope = encrypt_message(session,{'session_id':session.session_id,'action':'rotate'},'session_control',now=self.clock())
                publish(device_topic(device_id,MessageType.COMMAND),canonical_json(envelope))
                self.invalidate_device_sessions(device_id)
                self.repository.record_event('session_rotation',device_id,session.session_id)

    def shutdown(self) -> None:
        with self.lock:
            self.repository.invalidate_sessions()
            for session in self.sessions.values():
                session.authenticated = False
            self.sessions.clear()
            self.handshake.pending.clear()
            self.handshake.challenges.clear()
