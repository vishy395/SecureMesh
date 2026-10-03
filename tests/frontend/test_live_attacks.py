"""Actual Mosquitto + FastAPI + simulator subprocesses; no fake transport."""
import os
import json
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from securemesh.config import Settings
from securemesh.protocol import MessageType, device_topic, parse_json
from securemesh.security.identity import certificate_pem, generate_private_key, issue_server_certificate, save_private_key, issue_device_certificate
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
def test_live_stage5_attack_suite_and_dashboard(tmp_path, identity, page):
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
    registry_service = DeviceService(repository, ca)
    for number in (2,3):
        device_id = f'device-{number:02}'
        key = generate_private_key()
        cert = issue_device_certificate(device_id,key,ca_key,ca)
        directory = tmp_path / 'devices' / device_id
        directory.mkdir(parents=True)
        save_private_key(key,directory/'device.key.pem')
        (directory/'device.crt.pem').write_bytes(certificate_pem(cert))
        registry_service.register_device(device_id,certificate_pem(cert))
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
    logs = []

    def launch(command, name):
        output = (tmp_path / f"{name}.log").open("wb")
        logs.append(output)
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=creationflags)
        processes.append(process)
        return process

    from playwright.sync_api import expect
    screenshots=ROOT/'runtime/stage5-review'
    screenshots.mkdir(parents=True,exist_ok=True)
    try:
        launch([executable,'-c',str(config)],'broker')
        launch([sys.executable,'-m','securemesh.server.main'],'server')
        url=f'http://127.0.0.1:{api_port}'
        with httpx.Client(timeout=2,trust_env=False) as api:
            wait_until(lambda:api.get(url+'/health').json().get('mqtt')=='connected')
            for number in (1,2,3):
                launch([sys.executable,'-m','securemesh.device.main','--device-id',f'device-{number:02}','--interval','0.2'],f'device-{number:02}')
            wait_until(lambda:len({row['device_id'] for row in repository.list_telemetry()})==3)
            page.goto(url)
            expect(page.get_by_role('heading',name='Operational overview')).to_be_visible()
            for number in (1,2,3):
                response=api.post(url+f'/api/devices/device-{number:02}/commands',json={'command_type':'START','parameters':{}})
                assert response.status_code==201
            wait_until(lambda:sum(row['status']=='EXECUTED' for row in repository.list_commands())==3)
            demo=launch([sys.executable,'-m','securemesh.attacks.main','all','--url',url],'stage5-attacks')
            assert demo.wait(timeout=90)==0,(tmp_path/'stage5-attacks.log').read_text()
            results=json.loads((tmp_path/'stage5-attacks.log').read_text())
            assert len(results)==12
            assert all(row['observed_result']=='BLOCKED' and row['security_event_created'] for row in results)
            page.get_by_role('navigation').get_by_role('link',name='Security events').click()
            page.get_by_role('button',name='Refresh',exact=True).click()
            for code in ('REPLAY_ATTEMPT','INVALID_AUTHENTICATION_TAG','INVALID_SIGNATURE','INVALID_CERTIFICATE','UNKNOWN_DEVICE','STALE_MESSAGE','REVOKED_DEVICE','REVOKED_DEVICE_COMMAND_ATTEMPT','DUPLICATE_COMMAND'):
                expect(page.get_by_role('table').get_by_text(code,exact=True).first).to_be_visible()
            page.screenshot(path=str(screenshots/'security-events.png'),full_page=True)
            (screenshots/'attack-results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
            snapshot=api.get(url+'/api/dashboard?limit=500').json()
            assert snapshot['totals']['revoked_devices']==1 and snapshot['totals']['authenticated_devices']==2
            assert all(not row['active'] for row in repository.list_sessions() if row['device_id']=='device-02')
            counts={row['device_id']:row['telemetry_count'] for row in snapshot['devices']}
            wait_until(lambda:all(row['telemetry_count']>counts[row['device_id']] for row in api.get(url+'/api/dashboard').json()['devices'] if row['device_id'] in ('device-01','device-03')))
            assert next(row['telemetry_count'] for row in api.get(url+'/api/dashboard').json()['devices'] if row['device_id']=='device-02')==counts['device-02']
            print('Stage 5 live: 12 verified BLOCKED results; 3 normal commands acknowledged; real dashboard displayed attack events; device-01/device-03 continued after revocation.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        for output in logs:output.close()
