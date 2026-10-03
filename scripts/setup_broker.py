"""Offline local-only Mosquitto credential/config initialization."""
import argparse
import secrets
import subprocess
from pathlib import Path

from securemesh.config import Settings
from securemesh.security.identity import write_new_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password-tool", default="mosquitto_passwd", help="Path to mosquitto_passwd executable")
    args = parser.parse_args()
    settings = Settings.from_env()
    directory = settings.runtime_dir / "mqtt"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    password_file = (directory / "passwords").resolve()
    credentials = directory / "client.env"
    config = directory / "mosquitto.conf"
    if any(path.exists() for path in (password_file, credentials, config)):
        parser.exit(1, "Broker files already exist; refusing to replace credentials\n")
    password = secrets.token_urlsafe(32)
    try:
        write_new_file(password_file, f"securemesh:{password}\n".encode(), private=True)
        # Hash in place: no password appears in subprocess arguments or output.
        subprocess.run([args.password_tool, "-U", str(password_file)], check=True, capture_output=True)
        write_new_file(credentials, f"SECUREMESH_MQTT_USERNAME=securemesh\nSECUREMESH_MQTT_PASSWORD={password}\n".encode(), private=True)
        text = (f"listener {settings.mqtt_port} 127.0.0.1\nallow_anonymous false\npersistence false\n"
                f"password_file {password_file.as_posix()}\nmax_packet_size 65536\n")
        write_new_file(config, text.encode())
    except (OSError, subprocess.CalledProcessError):
        # Only files created by this invocation are removed; no secret error output.
        for path in (password_file, credentials, config):
            if path.exists():
                path.unlink()
        parser.exit(1, "Broker initialization failed; check the password-tool path\n")
    print(f"Broker initialized. Start Mosquitto with: -c {config}")


if __name__ == "__main__":
    main()
