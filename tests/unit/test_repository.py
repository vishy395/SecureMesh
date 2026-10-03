import pytest

from securemesh.security.identity import certificate_pem
from securemesh.server.repository import RegistryError


def test_registration_retrieval_listing_and_revocation(registry, identity):
    repository, service = registry
    assert repository.list_devices() == []
    record = service.register_device("device-01", certificate_pem(identity[3]))
    assert record["device_id"] == "device-01"
    assert record["status"] == "registered"
    assert record["last_seen"] is None
    assert repository.get_device("device-01") == record
    assert repository.list_devices() == [record]
    assert repository.get_device("missing") is None
    with pytest.raises(RegistryError):
        service.register_device("device-01", certificate_pem(identity[3]))
    service.revoke_device("device-01")
    revoked = repository.get_device("device-01")
    assert revoked["status"] == "revoked"
    assert revoked["revoked_at"] is not None
    service.revoke_device("device-01")
    assert repository.get_device("device-01")["revoked_at"] == revoked["revoked_at"]
    with pytest.raises(RegistryError):
        repository.revoke_device("missing")
