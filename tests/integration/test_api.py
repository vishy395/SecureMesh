from fastapi.testclient import TestClient

from securemesh.security.identity import certificate_pem
from securemesh.server.main import create_app
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService


def test_health_and_devices(settings, identity):
    repository = DeviceRepository(settings.database_path)
    repository.initialize()
    DeviceService(repository, identity[1]).register_device("device-01", certificate_pem(identity[3]))
    with TestClient(create_app(settings)) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "running"
        response = client.get("/api/devices")
        assert response.status_code == 200
        devices = response.json()
        assert devices[0]["device_id"] == "device-01"
        assert "certificate" not in devices[0]
        assert not any("key" in name for name in devices[0])


def test_server_needs_no_ca_private_key(settings, monkeypatch):
    from pathlib import Path
    original = Path.read_bytes

    def guard(path):
        assert "key" not in path.name, "Server attempted to read private key"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guard)
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/devices").json() == []
