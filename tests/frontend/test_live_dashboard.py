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
def test_live_dashboard_three_devices_commands_and_revocation(tmp_path, identity, page):
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

    from playwright.sync_api import expect
    import re
    screenshots=ROOT/'runtime/stage4-review'
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
            for number in (1,2,3):expect(page.get_by_role('link',name=f'device-{number:02}',exact=True)).to_be_visible()
            wait_until(lambda:len(repository.list_telemetry())>=45)
            page.get_by_role('button',name='Refresh',exact=True).click()
            expect(page.locator('.metric-value').nth(4)).not_to_have_text('6')
            page.screenshot(path=str(screenshots/'overview-desktop.png'),full_page=True)
            first_count=repository.list_telemetry()[0]['id']
            wait_until(lambda:repository.list_telemetry()[0]['id']>first_count)
            page.get_by_role('navigation').get_by_role('link',name='Command center').click()
            expect(page.get_by_role('heading',name='Command center',exact=True)).to_be_visible()
            def issue(device_id,kind,params=None):
                page.locator('#commandDevice').select_option(device_id)
                page.locator('#commandKind').select_option(kind)
                if kind=='CHANGE_THRESHOLD':page.locator('#threshold').fill(str(params['threshold']))
                if kind=='UPDATE_CONFIG':page.locator('#interval').fill(str(params['telemetry_interval']))
                page.get_by_role('button',name=re.compile('Review command')).click()
                expect(page.get_by_role('dialog')).to_be_visible()
                if not repository.list_commands():
                    page.get_by_role('dialog').get_by_role('button',name='Cancel').click()
                    assert not repository.list_commands()
                    page.get_by_role('button',name=re.compile('Review command')).click()
                page.get_by_role('dialog').get_by_role('button',name='Confirm').click()
                expect(page.locator('.command-selected').get_by_role('heading',name=re.compile(kind+' .* '+device_id))).to_be_visible(timeout=12000)
                expect(page.locator('.command-selected').get_by_text(re.compile('Acknowledgement: EXECUTED'))).to_be_visible(timeout=12000)
                latest=repository.list_commands()[0]
                assert latest['device_id']==device_id and latest['command_type']==kind and latest['status']=='EXECUTED'
                return latest
            issue('device-01','START')
            issue('device-02','CHANGE_THRESHOLD',{'threshold':35.5})
            issue('device-03','STOP')
            issue('device-01','UPDATE_CONFIG',{'telemetry_interval':.5})
            old_sid=next(row['session_id'] for row in repository.list_sessions() if row['device_id']=='device-01' and row['active'])
            issue('device-01','RESTART')
            wait_until(lambda:any(row['device_id']=='device-01' and row['active'] and row['session_id']!=old_sid for row in repository.list_sessions()))
            page.screenshot(path=str(screenshots/'commands-desktop.png'),full_page=True)
            page.get_by_role('navigation').get_by_role('link',name='Devices',exact=True).click()
            page.get_by_role('link',name='device-02',exact=True).click()
            expect(page.get_by_role('heading',name='device-02',exact=True)).to_be_visible()
            page.get_by_role('button',name='Revoke device',exact=True).click()
            page.get_by_role('dialog').get_by_role('button',name='Confirm').click()
            expect(page.get_by_role('button',name='Device revoked',exact=True)).to_be_disabled()
            assert all(not row['active'] for row in repository.list_sessions() if row['device_id']=='device-02')
            page.screenshot(path=str(screenshots/'revoked-device.png'),full_page=True)
            page.get_by_role('navigation').get_by_role('link',name='Security events').click()
            expect(page.get_by_role('table').get_by_text('DEVICE_REVOCATION',exact=True)).to_be_visible()
            wait_until(lambda:any(row['event_type']=='revoked_device' for row in repository.list_security_events()))
            page.get_by_role('button',name='Refresh',exact=True).click()
            expect(page.get_by_role('table').get_by_text('REVOKED_DEVICE',exact=True).first).to_be_visible()
            page.screenshot(path=str(screenshots/'security-desktop.png'),full_page=True)
            page.get_by_role('navigation').get_by_role('link',name='Overview',exact=True).click()
            expect(page.get_by_role('heading',name='Operational overview')).to_be_visible()
            page.screenshot(path=str(screenshots/'overview-revoked.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            expect(page.locator('.chart')).to_have_attribute('viewBox','0 0 326 180')
            page.screenshot(path=str(screenshots/'overview-mobile.png'),full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            snapshot=api.get(url+'/api/dashboard').json()
            assert snapshot['totals']['revoked_devices']==1 and snapshot['totals']['authenticated_devices']==2
            wire=json.dumps(snapshot)
            assert all(name not in wire for name in ('private_key','session_key','shared_secret','BEGIN PRIVATE KEY'))
            print('Stage 4 live browser: 3 devices shown; all 5 commands issued via UI and acknowledged; restart renewed session; device-02 revoked; security decisions shown; desktop/mobile screenshots captured.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        for output in logs:output.close()
