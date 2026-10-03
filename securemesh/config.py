"""Configuration without loading offline CA secrets into the server."""
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    runtime_dir: Path = Path("runtime")
    database_path: Path = Path("runtime/securemesh.db")
    ca_cert_path: Path = Path("runtime/ca/ca.crt.pem")
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    mqtt_host: str = "127.0.0.1"
    mqtt_port: int = 1883
    mqtt_enabled: bool = False
    mqtt_username: str | None = None
    mqtt_password: str | None = field(default=None, repr=False)
    server_identity: str = "control-center"
    server_cert_path: Path = Path("runtime/server/server.crt.pem")
    server_key_path: Path = Path("runtime/server/server.key.pem")
    session_ttl_seconds: int = 600
    handshake_ttl_seconds: int = 15
    max_clock_skew_seconds: int = 5
    telemetry_max_age_seconds: int = 30
    max_messages_per_session: int = 100000
    max_pending_handshakes: int = 128
    replay_policy: str = "strict_monotonic"

    def __post_init__(self) -> None:
        if self.replay_policy != "strict_monotonic":
            raise ValueError("Only strict_monotonic replay protection is supported")
        for name in ("session_ttl_seconds", "handshake_ttl_seconds", "telemetry_max_age_seconds",
                     "max_messages_per_session", "max_pending_handshakes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_clock_skew_seconds < 0:
            raise ValueError("Clock skew cannot be negative")
        if self.max_messages_per_session > 2**32 - 1:
            raise ValueError("Session message limit exceeds safe policy")

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(override=False)
        runtime = Path(os.getenv("SECUREMESH_RUNTIME_DIR", "runtime"))
        # Local broker setup writes credentials here, outside tracked source/config.
        load_dotenv(runtime / "mqtt/client.env", override=False)
        return cls(
            runtime_dir=runtime,
            database_path=Path(os.getenv("SECUREMESH_DATABASE_PATH", str(runtime / "securemesh.db"))),
            ca_cert_path=Path(os.getenv("SECUREMESH_CA_CERT_PATH", str(runtime / "ca/ca.crt.pem"))),
            server_host=os.getenv("SECUREMESH_SERVER_HOST", "127.0.0.1"),
            server_port=_port("SECUREMESH_SERVER_PORT", 8000),
            mqtt_host=os.getenv("SECUREMESH_MQTT_HOST", "127.0.0.1"),
            mqtt_port=_port("SECUREMESH_MQTT_PORT", 1883),
            mqtt_enabled=_boolean("SECUREMESH_MQTT_ENABLED", False),
            mqtt_username=os.getenv("SECUREMESH_MQTT_USERNAME") or None,
            mqtt_password=os.getenv("SECUREMESH_MQTT_PASSWORD") or None,
            server_identity=os.getenv("SECUREMESH_SERVER_IDENTITY", "control-center"),
            server_cert_path=Path(os.getenv("SECUREMESH_SERVER_CERT_PATH", str(runtime / "server/server.crt.pem"))),
            server_key_path=Path(os.getenv("SECUREMESH_SERVER_KEY_PATH", str(runtime / "server/server.key.pem"))),
            session_ttl_seconds=int(os.getenv("SECUREMESH_SESSION_TTL_SECONDS", "600")),
            handshake_ttl_seconds=int(os.getenv("SECUREMESH_HANDSHAKE_TTL_SECONDS", "15")),
            max_clock_skew_seconds=int(os.getenv("SECUREMESH_MAX_CLOCK_SKEW_SECONDS", "5")),
            telemetry_max_age_seconds=int(os.getenv("SECUREMESH_TELEMETRY_MAX_AGE_SECONDS", "30")),
            max_messages_per_session=int(os.getenv("SECUREMESH_MAX_MESSAGES_PER_SESSION", "100000")),
            max_pending_handshakes=int(os.getenv("SECUREMESH_MAX_PENDING_HANDSHAKES", "128")),
            replay_policy=os.getenv("SECUREMESH_REPLAY_POLICY", "strict_monotonic"),
        )


def _port(name: str, default: int) -> int:
    port = int(os.getenv(name, str(default)))
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return value == "true"
