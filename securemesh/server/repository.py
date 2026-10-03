"""Small SQLite registry; private keys are never stored here."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


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
            result = connection.execute("""UPDATE devices SET status = 'revoked',
                revoked_at = COALESCE(revoked_at, ?) WHERE device_id = ?""",
                (datetime.now(timezone.utc).isoformat(), device_id))
            if result.rowcount != 1:
                raise RegistryError("Unknown device")
