"""Configuration without loading offline CA secrets into the server."""
import os
from dataclasses import dataclass
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

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(override=False)
        runtime = Path(os.getenv("SECUREMESH_RUNTIME_DIR", "runtime"))
        return cls(
            runtime_dir=runtime,
            database_path=Path(os.getenv("SECUREMESH_DATABASE_PATH", str(runtime / "securemesh.db"))),
            ca_cert_path=Path(os.getenv("SECUREMESH_CA_CERT_PATH", str(runtime / "ca/ca.crt.pem"))),
            server_host=os.getenv("SECUREMESH_SERVER_HOST", "127.0.0.1"),
            server_port=_port("SECUREMESH_SERVER_PORT", 8000),
            mqtt_host=os.getenv("SECUREMESH_MQTT_HOST", "127.0.0.1"),
            mqtt_port=_port("SECUREMESH_MQTT_PORT", 1883),
        )


def _port(name: str, default: int) -> int:
    port = int(os.getenv(name, str(default)))
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port
