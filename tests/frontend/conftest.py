"""Real browser against a real isolated FastAPI process."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
import httpx
import pytest
from playwright.sync_api import sync_playwright
from securemesh.security.identity import certificate_pem
from securemesh.server.repository import DeviceRepository

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture(scope='session')
def browser():
    candidates=[os.getenv('SECUREMESH_BROWSER_EXE'), r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',r'C:\Program Files\Google\Chrome\Application\chrome.exe']
    executable=next((path for path in candidates if path and Path(path).exists()),None)
    with sync_playwright() as pw:
        instance=pw.chromium.launch(executable_path=executable,headless=True)
        yield instance
        instance.close()

@pytest.fixture
def dashboard_server(tmp_path,identity):
    ca_path=tmp_path/'ca.crt.pem'
    ca_path.write_bytes(certificate_pem(identity[1]))
    repo=DeviceRepository(tmp_path/'dashboard.db')
    repo.initialize()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env=os.environ.copy()
    env.update({'SECUREMESH_CA_CERT_PATH':str(ca_path),'SECUREMESH_DATABASE_PATH':str(repo.database_path),
                'SECUREMESH_MQTT_ENABLED':'false','SECUREMESH_SERVER_HOST':'127.0.0.1','SECUREMESH_SERVER_PORT':str(port)})
    output=(tmp_path/'server.log').open('wb')
    process=subprocess.Popen([sys.executable,'-m','securemesh.server.main'],cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    url=f'http://127.0.0.1:{port}'
    try:
        deadline=time.monotonic()+15
        with httpx.Client(trust_env=False,timeout=1) as api:
            while time.monotonic()<deadline:
                try:
                    if api.get(url+'/health').status_code==200: break
                except httpx.HTTPError: pass
                time.sleep(.1)
            else: raise AssertionError('Dashboard server did not start')
        yield url,repo
    finally:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
        output.close()

@pytest.fixture
def page(browser):
    context=browser.new_context(viewport={'width':1440,'height':1000})
    page=context.new_page()
    errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    yield page
    context.close()
    assert not errors,errors
