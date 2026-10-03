"""Small SQLite registry; private keys are never stored here."""
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from securemesh.security.sessions import Session


class RegistryError(ValueError):
    """Registry operation cannot be completed."""


class DeviceRepository:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize_commands()
        with self._connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                certificate_fingerprint TEXT NOT NULL UNIQUE,
                certificate TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                revoked_at TEXT,
                status TEXT NOT NULL CHECK(status IN ('registered', 'revoked')),
                last_seen TEXT
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                receive_sequence INTEGER NOT NULL DEFAULT 0,
                send_sequence INTEGER NOT NULL DEFAULT 0,
                authenticated INTEGER NOT NULL, active INTEGER NOT NULL,
                transcript_hash TEXT NOT NULL
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
                session_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                timestamp INTEGER NOT NULL, received_at INTEGER NOT NULL,
                payload TEXT NOT NULL, UNIQUE(session_id, sequence)
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
                device_id TEXT, session_id TEXT, recorded_at TEXT NOT NULL
            )""")

    def initialize_commands(self) -> None:
        with self._connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS commands (
                command_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
                command_type TEXT NOT NULL, parameters TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                status TEXT NOT NULL, session_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                acknowledgement TEXT, created_at INTEGER NOT NULL, completed_at INTEGER)""")

    def create_command(self, payload: dict) -> None:
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            result = db.execute("""UPDATE sessions SET send_sequence=?
                WHERE session_id=? AND device_id=? AND active=1 AND authenticated=1
                AND expires_at>? AND send_sequence<?
                AND EXISTS (SELECT 1 FROM devices WHERE device_id=? AND status='registered' AND revoked_at IS NULL)""",
                (payload['sequence'],payload['session_id'],payload['target_device_id'],
                 payload['issued_at'],payload['sequence'],payload['target_device_id']))
            if result.rowcount!=1: raise RegistryError('Command session state changed')
            db.execute("""INSERT INTO commands
                (command_id,device_id,command_type,parameters,issued_at,expires_at,status,session_id,sequence,created_at)
                VALUES (?,?,?,?,?,?,'CREATED',?,?,?)""",
                (payload['command_id'],payload['target_device_id'],payload['command_type'],
                 json.dumps(payload['parameters']),payload['issued_at'],payload['expires_at'],
                 payload['session_id'],payload['sequence'],payload['issued_at']))

    def command_status(self, command_id: str, status: str) -> None:
        with self._connection() as db:
            completed = int(datetime.now(timezone.utc).timestamp() * 1000) if status == 'FAILED' else None
            db.execute("UPDATE commands SET status=?,completed_at=? WHERE command_id=? AND status='CREATED'", (status,completed,command_id))

    def list_commands(self) -> list[dict]:
        with self._connection() as db:
            rows = db.execute('SELECT * FROM commands ORDER BY created_at DESC LIMIT 100').fetchall()
            return [{**dict(row), 'parameters':json.loads(row['parameters']),
                     'acknowledgement':json.loads(row['acknowledgement']) if row['acknowledgement'] else None} for row in rows]

    def get_command(self, command_id: str) -> dict | None:
        with self._connection() as db:
            row = db.execute('SELECT * FROM commands WHERE command_id=?', (command_id,)).fetchone()
            if row is None: return None
            return {**dict(row), 'parameters':json.loads(row['parameters']),
                    'acknowledgement':json.loads(row['acknowledgement']) if row['acknowledgement'] else None}

    def store_ack(self, session, envelope, payload, now):
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            result = db.execute("""UPDATE sessions SET receive_sequence=?
                WHERE session_id=? AND active=1 AND authenticated=1 AND expires_at>?
                AND receive_sequence<? AND EXISTS (SELECT 1 FROM devices
                WHERE device_id=? AND status='registered' AND revoked_at IS NULL)""",
                (envelope['sequence'],session.session_id,now,envelope['sequence'],session.device_id))
            if result.rowcount != 1: raise RegistryError('Invalid acknowledgement session')
            status = 'EXECUTED' if payload['status']=='ALREADY_PROCESSED' else payload['status']
            db.execute("""UPDATE commands SET status=?,acknowledgement=?,completed_at=?
                WHERE command_id=? AND status IN ('CREATED','SENT')""",
                (status,json.dumps(payload),now,payload['command_id']))

    def get_session(self, session_id):
        with self._connection() as db:
            row = db.execute('SELECT * FROM sessions WHERE session_id=?',(session_id,)).fetchone()
            return dict(row) if row else None

    def invalidate_device_sessions(self, device_id):
        with self._connection() as db:
            db.execute('UPDATE sessions SET active=0 WHERE device_id=?', (device_id,))

    def expire_commands(self, now):
        with self._connection() as db:
            db.execute("UPDATE commands SET status='EXPIRED',completed_at=? WHERE expires_at<=? AND status IN ('CREATED','SENT')", (now,now))

    def invalidate_sessions(self, session_id: str | None = None) -> None:
        with self._connection() as connection:
            if session_id is None:
                connection.execute("UPDATE sessions SET active = 0")
            else:
                connection.execute("UPDATE sessions SET active = 0 WHERE session_id = ?", (session_id,))

    def create_session(self, session: "Session") -> None:
        # Deliberate metadata allowlist: no serialization of Session/key objects.
        with self._connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            device = connection.execute("""SELECT device_id FROM devices
                WHERE device_id=? AND status='registered' AND revoked_at IS NULL""",
                (session.device_id,)).fetchone()
            if device is None:
                raise RegistryError('Device changed before session creation')
            connection.execute("UPDATE sessions SET active = 0 WHERE device_id = ?", (session.device_id,))
            connection.execute("""INSERT INTO sessions
                (session_id, device_id, created_at, expires_at, receive_sequence, send_sequence,
                 authenticated, active, transcript_hash) VALUES (?, ?, ?, ?, 0, ?, 1, 1, ?)""",
                (session.session_id, session.device_id, session.created_at, session.expires_at,
                 session.send_sequence, session.transcript_hash))

    def store_telemetry(self, session_id: str, device_id: str, sequence: int,
                        payload: dict, received_at: int) -> None:
        with self._connection() as connection:
            # This transaction commits replay state, telemetry and last_seen together.
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute("""UPDATE sessions SET receive_sequence = ?
                WHERE session_id = ? AND device_id = ? AND active = 1 AND authenticated = 1
                AND expires_at > ? AND receive_sequence < ?
                AND EXISTS (SELECT 1 FROM devices WHERE device_id = ? AND revoked_at IS NULL AND status = 'registered')""",
                (sequence, session_id, device_id, received_at, sequence, device_id))
            if result.rowcount != 1:
                raise RegistryError("Session state changed before telemetry commit")
            connection.execute("""INSERT INTO telemetry
                (device_id, session_id, sequence, timestamp, received_at, payload) VALUES (?, ?, ?, ?, ?, ?)""",
                (device_id, session_id, sequence, payload["timestamp"], received_at,
                 json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)))
            connection.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                               (datetime.fromtimestamp(received_at / 1000, timezone.utc).isoformat(), device_id))

    def record_event(self, event_type: str, device_id: str | None = None,
                     session_id: str | None = None) -> None:
        with self._connection() as connection:
            connection.execute("""INSERT INTO security_events
                (event_type, device_id, session_id, recorded_at) VALUES (?, ?, ?, ?)""",
                (event_type, device_id, session_id, datetime.now(timezone.utc).isoformat()))

    def list_sessions(self) -> list[dict]:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 100")]

    def list_telemetry(self, limit: int = 100) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]

    def list_security_events(self, limit: int = 100) -> list[dict]:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))]

    def register_device(self, device_id: str, certificate_fingerprint: str,
                        certificate: str) -> dict:
        try:
            with self._connection() as connection:
                connection.execute("""INSERT INTO devices
                    (device_id, certificate_fingerprint, certificate, registered_at, status)
                    VALUES (?, ?, ?, ?, 'registered')""",
                    (device_id, certificate_fingerprint, certificate, datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError as exc:
            # Never replace a pinned identity or implicitly reactivate a revoked device.
            raise RegistryError("Device ID or certificate is already registered") from exc
        device = self.get_device(device_id)
        if device is None:
            raise RegistryError("Registered device could not be retrieved")
        return device

    def get_device(self, device_id: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            return dict(row) if row else None

    def list_devices(self) -> list[dict]:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM devices ORDER BY device_id")]

    def revoke_device(self, device_id: str) -> None:
        with self._connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            timestamp = datetime.now(timezone.utc).isoformat()
            active = connection.execute(
                'SELECT session_id FROM sessions WHERE device_id=? AND active=1',
                (device_id,),
            ).fetchall()
            result = connection.execute("""UPDATE devices SET status = 'revoked',
                revoked_at = COALESCE(revoked_at, ?) WHERE device_id = ?""",
                (timestamp, device_id))
            if result.rowcount != 1:
                raise RegistryError("Unknown device")
            connection.execute("UPDATE sessions SET active=0 WHERE device_id=?", (device_id,))
            for row in active:
                connection.execute("""INSERT INTO security_events
                    (event_type,device_id,session_id,recorded_at)
                    VALUES ('session_invalidation',?,?,?)""", (device_id,row['session_id'],timestamp))
            connection.execute("""INSERT INTO security_events
                (event_type,device_id,recorded_at) VALUES ('device_revocation',?,?)""", (device_id,timestamp))
