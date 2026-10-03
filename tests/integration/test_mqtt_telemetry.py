"""Actual Mosquitto + FastAPI + simulator subprocesses; no fake transport."""
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from queue import Empty

import httpx
import pytest

from securemesh.config import Settings
from securemesh.protocol import MessageType, device_topic, parse_json
from securemesh.security.identity import certificate_pem, generate_private_key, issue_server_certificate, save_private_key
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService
from securemesh.transport.mqtt import MQTTTransport

ROOT = Path(__file__).resolve().parents[2]


def available_port() -> int:
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def wait_until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (httpx.HTTPError, ConnectionError):
            pass
        time.sleep(0.1)
    raise AssertionError("Live MQTT integration condition timed out")


@pytest.mark.mqtt
def test_live_authenticated_telemetry_and_replay(tmp_path, identity):
    executable = os.getenv("SECUREMESH_MOSQUITTO_EXE") or shutil.which("mosquitto")
    local = ROOT / "runtime/tools/mosquitto/mosquitto.exe"
    if executable is None and local.exists():
        executable = str(local)
    if not executable:
        pytest.skip("Install Mosquitto or set SECUREMESH_MOSQUITTO_EXE to run the live test")
    executable = str(Path(executable).resolve())
    passwd = Path(executable).with_name("mosquitto_passwd.exe" if os.name == "nt" else "mosquitto_passwd")
    assert passwd.exists(), "mosquitto_passwd must be installed alongside the broker"
    mqtt_port, api_port = available_port(), available_port()
    ca_key, ca, device_key, device_cert = identity
    ca_path = tmp_path / "ca.crt.pem"
    ca_path.write_bytes(certificate_pem(ca))
    device_dir = tmp_path / "devices/device-01"
    device_dir.mkdir(parents=True)
    save_private_key(device_key, device_dir / "device.key.pem")
    (device_dir / "device.crt.pem").write_bytes(certificate_pem(device_cert))
    server_key = generate_private_key()
    server_cert = issue_server_certificate("control-center", server_key, ca_key, ca)
    server_key_path, server_cert_path = tmp_path / "server.key.pem", tmp_path / "server.crt.pem"
    save_private_key(server_key, server_key_path)
    server_cert_path.write_bytes(certificate_pem(server_cert))
    password = secrets.token_urlsafe(32)
    password_file = tmp_path / "passwords"
    password_file.write_text(f"securemesh:{password}\n", encoding="utf-8")
    password_file.chmod(0o600)
    subprocess.run([str(passwd), "-U", str(password_file)], check=True, capture_output=True)
    config = tmp_path / "mosquitto.conf"
    config.write_text(f"listener {mqtt_port} 127.0.0.1\nallow_anonymous false\npersistence false\n"
                      f"password_file {password_file.as_posix()}\nmax_packet_size 65536\n", encoding="utf-8")
    database = tmp_path / "registry.db"
    repository = DeviceRepository(database)
    repository.initialize()
    DeviceService(repository, ca).register_device("device-01", certificate_pem(device_cert))
    settings = Settings(runtime_dir=tmp_path, database_path=database, ca_cert_path=ca_path,
                        mqtt_port=mqtt_port, mqtt_username="securemesh", mqtt_password=password)
    env = os.environ.copy()
    env.update({"SECUREMESH_RUNTIME_DIR": str(tmp_path), "SECUREMESH_DATABASE_PATH": str(database),
                "SECUREMESH_CA_CERT_PATH": str(ca_path), "SECUREMESH_SERVER_CERT_PATH": str(server_cert_path),
                "SECUREMESH_SERVER_KEY_PATH": str(server_key_path), "SECUREMESH_SERVER_IDENTITY": "control-center",
                "SECUREMESH_MQTT_ENABLED": "true", "SECUREMESH_MQTT_HOST": "127.0.0.1",
                "SECUREMESH_MQTT_PORT": str(mqtt_port), "SECUREMESH_SERVER_HOST": "127.0.0.1",
                "SECUREMESH_SERVER_PORT": str(api_port), "SECUREMESH_MQTT_USERNAME": "securemesh",
                "SECUREMESH_MQTT_PASSWORD": password})
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    processes = []
    observer = MQTTTransport(settings, "securemesh-test-observer", [device_topic("device-01", MessageType.TELEMETRY)])
    logs = []

    def launch(command, name):
        output = (tmp_path / f"{name}.log").open("wb")
        logs.append(output)
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=creationflags)
        processes.append(process)
        return process

    try:
        broker = launch([executable, "-c", str(config)], "broker")
        observer.start()
        server = launch([sys.executable, "-m", "securemesh.server.main"], "server")
        url = f"http://127.0.0.1:{api_port}"
        with httpx.Client(timeout=2, trust_env=False) as api:
            wait_until(lambda: api.get(url + "/health").json().get("mqtt") == "connected")
            device = launch([sys.executable, "-m", "securemesh.device.main", "--device-id", "device-01",
                             "--interval", "0.1", "--count", "12"], "device")
            captured = []
            deadline = time.monotonic() + 20
            while len(captured) < 12 and time.monotonic() < deadline:
                try:
                    captured.append(observer.messages.get(timeout=0.25))
                except Empty:
                    pass
            assert len(captured) >= 12
            assert device.wait(timeout=10) == 0
            wait_until(lambda: len(api.get(url + "/api/telemetry").json()) == 12)
            sessions = api.get(url + "/api/sessions").json()
            assert sessions[0]["receive_sequence"] == 12
            assert sessions[0]["authenticated"] == sessions[0]["active"] == 1
            assert api.get(url + "/api/devices").json()[0]["last_seen"] is not None
            sequences = sorted(row["sequence"] for row in api.get(url + "/api/telemetry").json())
            assert sequences == list(range(1, 13))
            for message in captured:
                wire = parse_json(message.payload)
                assert "ciphertext" in wire and "nonce" in wire
                assert not message.retained
                assert not any(field in message.payload for field in (b'"temperature"', b'"battery"', b'"cpu_usage"'))
            observer.publish(captured[-1].topic, captured[-1].payload)
            wait_until(lambda: any(event["event_type"] == "replay_attempt"
                                  for event in api.get(url + "/api/security-events").json()))
            assert len(api.get(url + "/api/telemetry").json()) == 12
            assert api.get(url + "/api/sessions").json()[0]["receive_sequence"] == 12
            assert broker.poll() is None and server.poll() is None
            print("Live validation: device-01 authenticated; 12 encrypted messages stored; replay rejected; sequence=12")
    finally:
        observer.stop()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for output in logs:
            output.close()
