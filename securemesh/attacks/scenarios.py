"""Local external MQTT actor using production protocol and persisted evidence."""
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from queue import Empty
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from securemesh.device.state import load_handshake
from securemesh.device.telemetry import generate_telemetry
from securemesh.protocol import MessageType, canonical_json, decode_bytes, device_topic, encode_bytes, handshake_topic, parse_json, validate_device_id
from securemesh.security.envelopes import accept_ready, encrypt_message, nonce_for_sequence
from securemesh.security.identity import generate_private_key, load_certificate, fingerprint
from securemesh.security.sessions import _sign, now_ms
from securemesh.transport.mqtt import MQTTTransport

def require_evidence(condition):
    if not condition:
        raise RuntimeError('Evidence verification failed')


SCENARIOS = ('replay', 'tamper', 'impersonate', 'mitm', 'stale', 'revoked')


def mutate(message, kind):
    result = dict(message)
    if kind == 'ciphertext':
        data = bytearray(decode_bytes(result['ciphertext']))
        data[0] ^= 1
        result['ciphertext'] = encode_bytes(bytes(data))
    elif kind == 'header':
        result['sequence'] += 1
        result['nonce'] = encode_bytes(nonce_for_sequence(decode_bytes(result['nonce'])[:4], result['sequence']))
    elif kind == 'ephemeral':
        result['device_ephemeral'] = encode_bytes(X25519PrivateKey.generate().public_key().public_bytes_raw())
    else:
        raise ValueError('Unknown mutation')
    return result


@dataclass(frozen=True)
class AttackResult:
    attack_type: str
    target: str
    attempted_at: str
    expected_result: str
    observed_result: str
    reason: str
    security_event_created: bool
    security_event: dict
    message_id: str
    session_id: str | None
    sequence: int | None
    command_id: str | None
    evidence: dict

    def public(self):
        return asdict(self)


class AttackRunner:
    def __init__(self, settings, url, timeout=20):
        parsed = urlsplit(url)
        if parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'} or parsed.username or parsed.password:
            raise ValueError('Attack API must be local loopback HTTP')
        if settings.mqtt_host not in {'127.0.0.1', 'localhost', '::1'}:
            raise ValueError('Attack MQTT broker must be local loopback')
        self.settings, self.url, self.timeout = settings, url.rstrip('/'), timeout
        self.opener = build_opener(ProxyHandler({}))
        self.transport = MQTTTransport(settings, 'securemesh-attacks-' + secrets.token_hex(8), [
            'securemesh/v1/devices/+/telemetry', 'securemesh/v1/devices/+/commands',
            'securemesh/v1/devices/+/handshake/response', 'securemesh/v1/devices/+/handshake/ready'])

    def api(self, path, body=None):
        request = Request(self.url + path, data=canonical_json(body) if body is not None else None,
                          headers={'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=5) as response:
            return json.load(response)

    def wait(self, predicate):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.05)
        raise RuntimeError('Evidence observation timed out')

    def capture(self, topic, predicate=lambda message: True):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                incoming = self.transport.messages.get(timeout=.1)
            except Empty:
                continue
            if incoming.topic == topic and not incoming.retained:
                message = parse_json(incoming.payload)
                if predicate(message):
                    return message
        raise RuntimeError('Protocol capture timed out')

    def events(self):
        return self.api('/api/security-events')

    def snapshot(self, sid):
        data = self.api('/api/dashboard?limit=500')
        session = next(row for row in data['sessions'] if row['session_id'] == sid)
        return {'receive_sequence': session['receive_sequence'], 'telemetry_count': next(
            row['telemetry_count'] for row in data['devices'] if row['device_id'] == session['device_id'])}

    def attempt(self, attack, target, topic, message, code, verify=lambda: {}, command_id=None, action=None):
        self.current_scenario = attack
        baseline = max((row['id'] for row in self.events()), default=0)
        attempted = datetime.now(timezone.utc).isoformat()
        (action or (lambda: self.transport.publish(topic, canonical_json(message))))()
        event = self.wait(lambda: next((row for row in self.events() if row['id'] > baseline and
            row['event_type'] == code and row['device_id'] == target and
            (not message.get('session_id') or row['session_id'] == message['session_id'])), None))
        evidence = verify()
        self.wait(lambda: any(row['id'] == event['id'] for row in self.api('/api/dashboard?limit=500')['events']))
        return AttackResult(attack, target, attempted, 'BLOCKED', 'BLOCKED', code, True, event,
            hashlib.sha256(canonical_json(message)).hexdigest(), message.get('session_id'),
            message.get('sequence'), command_id, evidence)

    def telemetry(self, target):
        topic = device_topic(target, MessageType.TELEMETRY)
        active = {row['session_id']: row['receive_sequence'] for row in self.api('/api/sessions')
                  if row['active'] and row['device_id'] == target}
        message = self.capture(topic, lambda row: row.get('session_id') in active and
                               row.get('sequence', 0) >= active[row['session_id']])
        self.wait(lambda: any(row['session_id'] == message['session_id'] and row['sequence'] == message['sequence']
                             for row in self.api('/api/telemetry')))
        return topic, message

    def unchanged_delivery(self, message):
        require_evidence(sum(row['session_id'] == message['session_id'] and row['sequence'] == message['sequence']
                   for row in self.api('/api/telemetry')) == 1)
        return {'original_stored_once': True, 'session': self.snapshot(message['session_id'])}

    def replay(self, target):
        topic, message = self.telemetry(target)
        results = [self.attempt('TELEMETRY_REPLAY', target, topic, message, 'replay_attempt', lambda: self.unchanged_delivery(message))]
        command = self.api(f'/api/devices/{target}/commands', {'command_type': 'CHANGE_THRESHOLD', 'parameters': {'threshold': 36.0}})
        envelope = self.capture(device_topic(target, MessageType.COMMAND), lambda m: m.get('sequence') == command['sequence'] and m.get('session_id') == command['session_id'])
        self.wait(lambda: any(row['command_id'] == command['command_id'] and row['status'] == 'EXECUTED' for row in self.api('/api/commands')))
        def verify():
            path = self.settings.runtime_dir / 'devices' / target / 'state.db'
            with sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True) as db:
                executed = db.execute("SELECT COUNT(*) FROM events WHERE event_type='command_executed'").fetchone()[0]
                require_evidence(db.execute('SELECT COUNT(*) FROM processed WHERE command_id=?', (command['command_id'],)).fetchone()[0] == 1)
            return {'processed_id_count': 1, 'execution_events': executed}
        before = verify()
        def after():
            evidence = verify()
            require_evidence(evidence == before)
            return evidence
        results.append(self.attempt('COMMAND_REPLAY', target, device_topic(target, MessageType.COMMAND), envelope, 'duplicate_command', after, command['command_id']))
        return results

    def tamper(self, target):
        topic, message = self.telemetry(target)
        return [self.attempt('TAMPER_' + kind.upper(), target, topic, mutate(message, kind),
            'invalid_authentication_tag', lambda: self.unchanged_delivery(message)) for kind in ('ciphertext', 'header')]

    def attacker_hello(self, target, certificate_device=None):
        # Only public victim certificates are read. Dedicated attacker key stays in memory.
        pem = (self.settings.runtime_dir / 'devices' / (certificate_device or target) / 'device.crt.pem').read_bytes()
        cert = load_certificate(pem)
        server = load_certificate(self.settings.server_cert_path.read_bytes())
        hello = {'version': 1, 'type': 'hello', 'device_id': target, 'server_identity': self.settings.server_identity,
            'server_fingerprint': fingerprint(server), 'certificate': pem.decode('ascii'), 'device_fingerprint': fingerprint(cert),
            'device_ephemeral': encode_bytes(X25519PrivateKey.generate().public_key().public_bytes_raw()),
            'device_challenge': encode_bytes(secrets.token_bytes(32)), 'timestamp': now_ms()}
        hello['signature'] = _sign(generate_private_key(), 'device-hello', canonical_json(hello))
        return hello

    def impersonate(self, target):
        results = []
        for kind, claimed, cert_device, code in (
            ('UNKNOWN_DEVICE', 'device-999', target, 'unknown_device'), ('WRONG_KEY', target, target, 'invalid_signature'),
            ('CERTIFICATE_MISMATCH', target, 'device-03' if target != 'device-03' else 'device-01', 'invalid_certificate')):
            hello = self.attacker_hello(claimed, cert_device)
            before = {row['session_id'] for row in self.api('/api/sessions')}
            def verify():
                require_evidence({row['session_id'] for row in self.api('/api/sessions')} == before)
                return {'no_session_created': True}
            results.append(self.attempt(kind, claimed, handshake_topic(claimed, 'hello'), hello, code, verify))
        return results

    def mitm(self, target):
        hello = load_handshake(self.settings, target).start()
        before = {row['session_id'] for row in self.api('/api/sessions')}
        def verify():
            require_evidence({row['session_id'] for row in self.api('/api/sessions')} == before)
            return {'no_session_created': True}
        return [self.attempt('EPHEMERAL_SUBSTITUTION', target, handshake_topic(target, 'hello'), mutate(hello, 'ephemeral'), 'invalid_signature', verify)]

    def stale(self, target):
        # Authorized fixture actor owns a disposable device session, never bypasses admission.
        handshake = load_handshake(self.settings, target)
        self.transport.publish(handshake_topic(target, 'hello'), canonical_json(handshake.start()))
        response = self.capture(handshake_topic(target, 'response'))
        finish = handshake.accept_response(response)
        self.transport.publish(handshake_topic(target, 'finish'), canonical_json(finish))
        ready = self.capture(handshake_topic(target, 'ready'), lambda m: m.get('session_id') == finish['session_id'])
        accept_ready(handshake.session, ready)
        session = handshake.session
        topic = device_topic(target, MessageType.TELEMETRY)
        payload = generate_telemetry()
        payload['timestamp'] = now_ms() - self.settings.telemetry_max_age_seconds * 1000 - 5000
        envelope = encrypt_message(session, payload, 'telemetry')
        before = self.snapshot(session.session_id)
        def verify():
            current = self.snapshot(session.session_id)
            require_evidence(current == before)
            fresh = encrypt_message(session, generate_telemetry(), 'telemetry')
            self.transport.publish(topic, canonical_json(fresh))
            self.wait(lambda: self.snapshot(session.session_id)['receive_sequence'] == fresh['sequence'])
            return {'before': before, 'after_rejection': current, 'fresh_sequence_accepted': fresh['sequence']}
        return [self.attempt('STALE_MESSAGE', target, topic, envelope, 'stale_message', verify)]

    def revoked(self, target):
        topic, message = self.telemetry(target)
        counts = {row['device_id']: row['telemetry_count'] for row in self.api('/api/dashboard')['devices']}
        self.api(f'/api/devices/{target}/revoke', {})
        require_evidence(all(not row['active'] for row in self.api('/api/sessions') if row['device_id'] == target))
        result = self.attempt('REVOKED_TELEMETRY', target, topic, message, 'revoked_device')
        hello = load_handshake(self.settings, target).start()
        authentication = self.attempt('REVOKED_AUTHENTICATION', target, handshake_topic(target, 'hello'), hello, 'revoked_device')
        def command():
            try:
                self.api(f'/api/devices/{target}/commands', {'command_type': 'START', 'parameters': {}})
            except HTTPError as exc:
                require_evidence(exc.code == 409 and json.load(exc)['detail'] == 'revoked_device')
            else:
                raise AssertionError('Revoked command accepted')
        command_result = self.attempt('REVOKED_COMMAND', target, '', {}, 'revoked_device_command_attempt', action=command)
        healthy = {key: value for key, value in counts.items() if key != target}
        self.wait(lambda: all(row['telemetry_count'] > healthy[row['device_id']] for row in self.api('/api/dashboard')['devices'] if row['device_id'] in healthy))
        return [result, authentication, command_result]

    def run(self, scenario, target):
        validate_device_id(target)
        if scenario == 'all':
            results = []
            for name in ('replay', 'tamper', 'impersonate', 'mitm'):
                results.extend(getattr(self, name)('device-01'))
            results.extend(self.stale('device-02'))
            results.extend(self.revoked('device-02'))
            return results
        return getattr(self, scenario)(target)
