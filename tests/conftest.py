from pathlib import Path

import pytest

from securemesh.config import Settings
from securemesh.security.identity import certificate_pem, create_ca, generate_private_key, issue_device_certificate
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService


@pytest.fixture
def identity():
    ca_key = generate_private_key()
    ca = create_ca(ca_key)
    key = generate_private_key()
    cert = issue_device_certificate("device-01", key, ca_key, ca)
    return ca_key, ca, key, cert


@pytest.fixture
def registry(tmp_path: Path, identity):
    repository = DeviceRepository(tmp_path / "registry.db")
    repository.initialize()
    return repository, DeviceService(repository, identity[1])


@pytest.fixture
def settings(tmp_path: Path, identity):
    ca_path = tmp_path / "ca.crt.pem"
    ca_path.write_bytes(certificate_pem(identity[1]))
    return Settings(runtime_dir=tmp_path, database_path=tmp_path / "registry.db", ca_cert_path=ca_path)
