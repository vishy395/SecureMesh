import pytest

from scripts.provision import initialize_ca, provision_device
from securemesh.security.identity import IdentityError, load_certificate
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService


def test_offline_provisioning(tmp_path):
    from securemesh.config import Settings
    settings = Settings(runtime_dir=tmp_path, database_path=tmp_path / "registry.db",
                        ca_cert_path=tmp_path / "ca/ca.crt.pem")
    key_path = tmp_path / "ca/ca.key.pem"
    initialize_ca(settings, key_path)
    with pytest.raises(IdentityError):
        initialize_ca(settings, key_path)
    repository = DeviceRepository(settings.database_path)
    repository.initialize()
    service = DeviceService(repository, load_certificate(settings.ca_cert_path.read_bytes()))
    for device_id in ["device-01", "device-02", "device-03"]:
        directory = provision_device(settings, key_path, device_id)
        assert sorted(path.name for path in directory.iterdir()) == ["device.crt.pem", "device.key.pem"]
        pem = (directory / "device.crt.pem").read_bytes()
        service.register_device(device_id, pem)
        assert service.validate_registered_device(device_id, pem)
    assert len(repository.list_devices()) == 3
    with pytest.raises(IdentityError):
        provision_device(settings, key_path, "device-01")
