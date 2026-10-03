"""Read-only dashboard projection. Never serializes live security objects."""
import json
from cryptography import x509
from securemesh.server.repository import DeviceRepository

ACCEPTED_EVENTS = {
    'session_authenticated', 'command_created', 'command_sent', 'command_executed',
    'duplicate_command', 'device_revocation', 'session_invalidation', 'session_rotation',
}
FAILED_EVENTS = {'command_failed', 'command_publish_failed', 'session_state_conflict', 'handshake_failure', 'handshake_capacity'}
BLOCKED_EVENTS = {
    'replay_attempt', 'command_replay', 'invalid_signature', 'invalid_authentication_tag',
    'stale_message', 'revoked_device', 'revoked_device_command_attempt', 'command_rejected',
    'invalid_command', 'invalid_parameters', 'unsupported_command', 'invalid_message',
    'invalid_certificate', 'unknown_device', 'invalid_session', 'expired_session',
    'expired_command', 'invalid_sequence', 'invalid_command_id', 'wrong_direction',
    'wrong_target_device', 'identity_mismatch', 'invalid_nonce', 'invalid_topic',
    'retained_message_rejected', 'protocol_version_mismatch', 'invalid_message_type',
    'expired_challenge', 'replayed_challenge', 'transcript_mismatch', 'invalid_telemetry',
    'invalid_ack', 'session_message_limit', 'invalid_ephemeral_key', 'server_identity_mismatch',
}
REASONS = {
    'replay_attempt': 'Authenticated sequence was already received.',
    'command_replay': 'Command delivery failed replay validation.',
    'invalid_signature': 'Identity signature did not verify.',
    'invalid_authentication_tag': 'Encrypted message authentication failed.',
    'stale_message': 'Message was outside the accepted freshness window.',
    'device_revocation': 'Device registration revoked by the operator.',
    'revoked_device': 'Communication from a revoked device was rejected.',
    'revoked_device_command_attempt': 'Command to a revoked device was rejected.',
    'session_invalidation': 'Session invalidated; history retained.',
    'session_rotation': 'Session rotation initiated or previous session replaced.',
    'session_authenticated': 'Device completed the authenticated handshake.',
    'command_created': 'Validated command metadata persisted.',
    'command_sent': 'Protected command published.',
    'command_executed': 'Authenticated execution acknowledgement received.',
    'duplicate_command': 'Duplicate acknowledged without another execution.',
    'command_rejected': 'Command was rejected by authorization or validation.',
    'handshake_failure': 'Authentication handshake did not complete.',
}


def event_presentation(code: str) -> dict:
    if code in ACCEPTED_EVENTS:
        status = 'ACCEPTED'
    elif code in FAILED_EVENTS:
        status = 'FAILED'
    elif code in BLOCKED_EVENTS:
        status = 'BLOCKED'
    else:
        status = 'INFO'
    severity = 'critical' if code == 'device_revocation' else 'error' if status in {'BLOCKED', 'FAILED'} else 'info'
    return {'status': status, 'severity': severity,
            'reason': REASONS.get(code, 'Recorded backend event: ' + code.replace('_', ' ') + '.')}


def dashboard_snapshot(repository: DeviceRepository, device_id: str | None, limit: int, now: int) -> dict:
    # One read transaction keeps counts, registration and histories consistent.
    with repository._connection() as db:
        db.execute('BEGIN')
        records = [dict(row) for row in db.execute('SELECT * FROM devices ORDER BY device_id')]
        if device_id is not None and not any(row['device_id'] == device_id for row in records):
            raise LookupError('unknown_device')
        sessions = [dict(row) for row in db.execute('SELECT * FROM sessions WHERE active=1 ORDER BY created_at DESC')]
        counts = {}
        for table in ('telemetry', 'commands'):
            counts[table] = {row['device_id']: row['total'] for row in db.execute(f'SELECT device_id,COUNT(*) AS total FROM {table} GROUP BY device_id')}
        devices = []
        for record in records:
            # Explicit public identity allowlist; certificate PEM never leaves storage.
            device = {key: record[key] for key in ('device_id','certificate_fingerprint','registered_at','revoked_at','last_seen')}
            try:
                certificate = x509.load_pem_x509_certificate(record['certificate'].encode('ascii'))
                valid_from = int(certificate.not_valid_before_utc.timestamp()*1000)
                valid_until = int(certificate.not_valid_after_utc.timestamp()*1000)
                certificate_status = 'EXPIRED' if now>=valid_until else 'NOT YET VALID' if now<valid_from else 'VALID'
            except (ValueError, UnicodeError):
                valid_from = valid_until = None
                certificate_status = 'UNKNOWN'
            device.update(certificate_valid_from=valid_from,certificate_valid_until=valid_until,certificate_status=certificate_status)
            device['state'] = 'REVOKED' if record['revoked_at'] or record['status']=='revoked' else 'ACTIVE'
            live = next((row for row in sessions if row['device_id']==record['device_id'] and row['authenticated'] and row['expires_at']>now), None)
            device['session'] = live if device['state']=='ACTIVE' else None
            latest = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 1', (record['device_id'],)).fetchone()
            device['latest_telemetry'] = {**dict(latest), 'payload':json.loads(latest['payload'])} if latest else None
            device['telemetry_count'] = counts['telemetry'].get(record['device_id'],0)
            device['command_count'] = counts['commands'].get(record['device_id'],0)
            devices.append(device)
        where = ' WHERE device_id=?' if device_id else ''
        args = (device_id,limit) if device_id else (limit,)
        telemetry = [{**dict(row),'payload':json.loads(row['payload'])} for row in db.execute('SELECT * FROM telemetry'+where+' ORDER BY id DESC LIMIT ?',args)]
        commands = [{**dict(row),'parameters':json.loads(row['parameters']),
                     'acknowledgement':json.loads(row['acknowledgement']) if row['acknowledgement'] else None}
                    for row in db.execute('SELECT * FROM commands'+where+' ORDER BY created_at DESC,command_id LIMIT ?',args)]
        events = [{**dict(row),**event_presentation(row['event_type'])} for row in db.execute('SELECT * FROM security_events'+where+' ORDER BY id DESC LIMIT ?',args)]
        historical_sessions = [dict(row) for row in db.execute('SELECT * FROM sessions'+where+' ORDER BY created_at DESC LIMIT ?',args)]
        event_counts = {row['event_type']:row['total'] for row in db.execute('SELECT event_type,COUNT(*) AS total FROM security_events GROUP BY event_type')}
        totals = {
            'total_devices':len(devices), 'active_devices':sum(row['state']=='ACTIVE' for row in devices),
            'authenticated_devices':sum(row['session'] is not None for row in devices),
            'revoked_devices':sum(row['state']=='REVOKED' for row in devices),
            'telemetry_received':sum(counts['telemetry'].values()), 'commands_issued':sum(counts['commands'].values()),
            'commands_executed':db.execute("SELECT COUNT(*) FROM commands WHERE status='EXECUTED'").fetchone()[0],
            'blocked_events':sum(count for code,count in event_counts.items() if code in BLOCKED_EVENTS),
        }
    return {'generated_at':now, 'totals':totals, 'devices':devices, 'sessions':historical_sessions,
            'telemetry':telemetry, 'commands':commands, 'events':events, 'history_limit':limit,
            'scope_device_id':device_id}
