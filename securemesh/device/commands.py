"""Durable simulator state and authenticated command execution."""
import hashlib
import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Callable

from securemesh.commands import validate_command, validate_command_id
from securemesh.protocol import canonical_json
from securemesh.security.envelopes import decrypt_message, encrypt_message
from securemesh.security.sessions import SecurityError, Session, now_ms


class CommandHandler:
    def __init__(
        self, path: Path, device_id: str, clock: Callable[[], int] = now_ms,
        event: Callable[[str], None] | None = None, max_clock_skew_ms: int = 5000,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path, self.device_id, self.clock = path, device_id, clock
        self.max_clock_skew_ms = max_clock_skew_ms
        self._event_callback = event or (lambda code: None)
        self.authorized = True
        self.lock = RLock()
        self.restart_requested = False
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, timestamp INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS deliveries (digest TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS processed (command_id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL)")
            initial = {
                "state": "RUNNING", "threshold": 35.0,
                "configuration": {"telemetry_interval": 2.0, "location_enabled": True},
                "last_command": None, "last_command_sequence": 0, "restart_count": 0,
            }
            db.execute("INSERT OR IGNORE INTO state VALUES (1, ?)", (json.dumps(initial),))

    def event(self, code: str) -> None:
        # Storage failures must still leave a sanitized log without hiding an ACK.
        try:
            with sqlite3.connect(self.path) as db:
                db.execute("INSERT INTO events (event_type,timestamp) VALUES (?,?)", (code, self.clock()))
        except sqlite3.Error:
            self._event_callback("device_event_storage_failed")
        self._event_callback(code)

    def acknowledgement(self, session: Session, payload: dict, status: str) -> dict:
        return encrypt_message(session, {
            "version": 1, "command_id": payload["command_id"],
            "device_id": self.device_id, "status": status, "timestamp": self.clock(),
            "command_sequence": payload["sequence"],
        }, "ack", now=self.clock())

    @property
    def state(self) -> dict:
        with sqlite3.connect(self.path) as db:
            return json.loads(db.execute("SELECT payload FROM state WHERE id=1").fetchone()[0])

    def process(self, session: Session, envelope: dict) -> dict:
        try:
            return self._process(session, envelope)
        except (SecurityError, ValueError, TypeError, KeyError) as exc:
            code = exc.code if isinstance(exc, SecurityError) else "invalid_command"
            self.event("command_replay" if code == "replay_attempt" else code)
            self.event("command_rejected")
            raise

    def _process(self, session: Session, envelope: dict) -> dict:
        with self.lock, session.lock:
            digest = hashlib.sha256(canonical_json(envelope)).hexdigest()
            try:
                payload = decrypt_message(session, envelope, "command", now=self.clock())
            except SecurityError as exc:
                if exc.code != "replay_attempt":
                    raise
                # GCM authentication precedes the envelope replay error. Only an
                # exact authenticated delivery already stored locally can get an ACK.
                with sqlite3.connect(self.path) as db:
                    row = db.execute("SELECT payload FROM deliveries WHERE digest=?", (digest,)).fetchone()
                if row is None:
                    raise
                payload = json.loads(row[0])

            # Bind routing and validate the ID before reflecting either in an ACK.
            validate_command_id(payload.get("command_id"))
            if payload.get("target_device_id") != self.device_id or session.device_id != self.device_id:
                raise SecurityError("wrong_target_device")
            try:
                validate_command(payload, envelope, session, self.clock(), skew=self.max_clock_skew_ms)
                if not self.authorized:
                    raise SecurityError("unauthorized_device")
            except (SecurityError, ValueError, TypeError) as exc:
                self.event(exc.code if isinstance(exc, SecurityError) else "invalid_command")
                self.event("command_rejected")
                session.receive_sequence = max(session.receive_sequence, envelope["sequence"])
                safe = {**payload, "sequence": envelope["sequence"]}
                return self.acknowledgement(session, safe, "REJECTED")

            try:
                status = self._execute(payload, digest)
            except sqlite3.Error:
                # All simulated effects and dedup records share one transaction.
                # A failed commit rolls both back, permitting a later safe retry.
                self.event("command_failed")
                return self.acknowledgement(session, payload, "FAILED")
            session.receive_sequence = max(session.receive_sequence, envelope["sequence"])
            self.event("duplicate_command" if status == "ALREADY_PROCESSED" else "command_executed")
            result = self.acknowledgement(session, payload, status)
            if payload["command_type"] == "RESTART" and status == "EXECUTED":
                self.restart_requested = True
            return result

    def _execute(self, payload: dict, digest: str) -> str:
        """Atomic local effect and command-ID/delivery deduplication commit."""
        with sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT payload FROM processed WHERE command_id=?", (payload["command_id"],)).fetchone()
            if previous:
                old = json.loads(previous[0])
                if any(old[key] != payload[key] for key in ("target_device_id", "command_type", "parameters")):
                    raise SecurityError("command_id_conflict")
                status = "ALREADY_PROCESSED"
            else:
                state = json.loads(db.execute("SELECT payload FROM state WHERE id=1").fetchone()[0])
                kind, parameters = payload["command_type"], payload["parameters"]
                if kind == "START":
                    state["state"] = "RUNNING"
                elif kind == "STOP":
                    state["state"] = "STOPPED"
                elif kind == "RESTART":
                    state["restart_count"] += 1
                    state["state"] = "RUNNING"
                elif kind == "CHANGE_THRESHOLD":
                    state["threshold"] = parameters["threshold"]
                elif kind == "UPDATE_CONFIG":
                    state["configuration"].update(parameters)
                state["last_command"] = payload["command_id"]
                state["last_command_sequence"] = payload["sequence"]
                db.execute("UPDATE state SET payload=? WHERE id=1", (json.dumps(state),))
                db.execute("INSERT INTO processed VALUES (?,?,?,?)", (payload["command_id"], digest, json.dumps(payload), "EXECUTED"))
                status = "EXECUTED"
            db.execute("INSERT OR IGNORE INTO deliveries VALUES (?,?)", (digest, json.dumps(payload)))
        return status
