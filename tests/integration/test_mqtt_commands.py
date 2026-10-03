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
def test_live_stage3_three_devices_commands_redelivery_revocation_rotation(tmp_path, identity):
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
    observer = MQTTTransport(settings, "securemesh-test-observer", ["securemesh/v1/devices/+/commands"])
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
            for number in (1,2,3):
                launch([sys.executable,"-m","securemesh.device.main","--device-id",f"device-{number:02}","--interval","0.1"],f"device-{number:02}")
            wait_until(lambda: {row['device_id'] for row in api.get(url+'/api/telemetry').json()} == {'device-01','device-02','device-03'})
            initial_sessions = {row['device_id']:row['session_id'] for row in api.get(url+'/api/sessions').json() if row['active']}
            assert len(initial_sessions)==3
            commands = {}
            for device_id, kind, params in [('device-01','START',{}),('device-02','CHANGE_THRESHOLD',{'threshold':35.0}),('device-03','STOP',{})]:
                response=api.post(url+f'/api/devices/{device_id}/commands',json={'command_type':kind,'parameters':params})
                assert response.status_code==201, response.text
                commands[device_id]=response.json()
            wait_until(lambda: len([row for row in api.get(url+'/api/commands').json() if row['status']=='EXECUTED'])==3)
            for device_id, expected_state in [('device-01','RUNNING'),('device-02','RUNNING'),('device-03','STOPPED')]:
                def state_matches():
                    rows=[row for row in api.get(url+'/api/telemetry').json() if row['device_id']==device_id]
                    return bool(rows) and rows[0]['payload']['device_state']['last_command']==commands[device_id]['command_id'] and rows[0]['payload']['device_state']['state']==expected_state
                wait_until(state_matches)
                with __import__('sqlite3').connect(tmp_path/'devices'/device_id/'state.db') as db:
                    assert db.execute('SELECT command_id FROM processed').fetchall()==[(commands[device_id]['command_id'],)]
            captured = []
            while len(captured)<3:
                captured.append(observer.messages.get(timeout=5))
            duplicate=next(message for message in captured if message.topic==device_topic('device-03',MessageType.COMMAND))
            observer.publish(duplicate.topic,duplicate.payload)
            observer.publish(duplicate.topic,duplicate.payload)
            wait_until(lambda: len([event for event in api.get(url+'/api/security-events').json() if event['event_type']=='duplicate_command' and event['device_id']=='device-03'])>=2)
            with __import__('sqlite3').connect(tmp_path/'devices/device-03/state.db') as db:
                assert db.execute('SELECT COUNT(*) FROM processed').fetchone()[0]==1
            # Restart simulates an event, ACKs first, and establishes a fresh session.
            restart=api.post(url+'/api/devices/device-01/commands',json={'command_type':'RESTART','parameters':{}})
            assert restart.status_code==201
            wait_until(lambda: any(row['command_id']==restart.json()['command_id'] and row['status']=='EXECUTED' for row in api.get(url+'/api/commands').json()))
            wait_until(lambda: any(row['device_id']=='device-01' and row['active'] and row['session_id']!=initial_sessions['device-01'] for row in api.get(url+'/api/sessions').json()))
            assert api.post(url+'/api/devices/device-03/sessions/rotate').status_code==200
            wait_until(lambda: any(row['device_id']=='device-03' and row['active'] and row['session_id']!=initial_sessions['device-03'] for row in api.get(url+'/api/sessions').json()))
            demo = launch([sys.executable,'-m','scripts.demo_stage3','--url',url], 'stage3-demo')
            assert demo.wait(timeout=30)==0, (tmp_path/'stage3-demo.log').read_text()
            assert api.post(url+'/api/devices/device-02/revoke').status_code==200
            sessions=api.get(url+'/api/sessions').json()
            assert all(not row['active'] for row in sessions if row['device_id']=='device-02')
            rejected=api.post(url+'/api/devices/device-02/commands',json={'command_type':'START','parameters':{}})
            assert rejected.status_code==409
            wait_until(lambda: any(event['event_type']=='revoked_device' and event['device_id']=='device-02' for event in api.get(url+'/api/security-events').json()))
            rows=repository.list_telemetry(10000)
            revoked_count=sum(row['device_id']=='device-02' for row in rows)
            counts={device_id:sum(row['device_id']==device_id for row in rows) for device_id in ('device-01','device-03')}
            wait_until(lambda: all(sum(row['device_id']==device_id for row in repository.list_telemetry(10000))>counts[device_id] for device_id in counts))
            assert sum(row['device_id']=='device-02' for row in repository.list_telemetry(10000))==revoked_count
            assert broker.poll() is None and server.poll() is None
            print('Stage 3 live: 3 devices authenticated and sent telemetry; targeted START/CHANGE_THRESHOLD/STOP acknowledged; duplicate delivered twice with one execution; restart and explicit rotation renewed sessions; device-02 revoked with telemetry and commands rejected; device-01/device-03 continued.')
    finally:
        observer.stop()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for output in logs: output.close()


@pytest.mark.mqtt
@pytest.mark.parametrize("trigger", ["expiration", "message_limit"])
def test_live_automatic_rotation(tmp_path, identity, trigger):
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
    env['SECUREMESH_SESSION_TTL_SECONDS'] = '1' if trigger=='expiration' else '600'
    env['SECUREMESH_MAX_MESSAGES_PER_SESSION'] = '100000' if trigger=='expiration' else '4'
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
        launch([executable,"-c",str(config)],"broker")
        observer.start()
        launch([sys.executable,"-m","securemesh.server.main"],"server")
        url=f"http://127.0.0.1:{api_port}"
        with httpx.Client(timeout=2,trust_env=False) as api:
            wait_until(lambda: api.get(url+'/health').json().get('mqtt')=='connected')
            device=launch([sys.executable,'-m','securemesh.device.main','--device-id','device-01','--interval','0.1','--count','20'],'device')
            assert device.wait(timeout=20)==0, (tmp_path/'device.log').read_text()
            wait_until(lambda: len(repository.list_telemetry())==20)
            sessions=repository.list_sessions()
            assert len(sessions)>=2
            assert sum(row['active'] for row in sessions)==1
            assert len({row['session_id'] for row in repository.list_telemetry()})>=2
            assert any(row['event_type']=='session_rotation' for row in repository.list_security_events())
    finally:
        observer.stop()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for output in logs: output.close()
