from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from securemesh.security.identity import (certificate_pem, fingerprint, load_certificate,
    load_private_key, save_private_key, validate_ca_certificate, validate_device_certificate)


def test_ca_generation_and_self_signature(identity):
    _, ca, _, _ = identity
    validate_ca_certificate(ca)
    ca.verify_directly_issued_by(ca)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_device_key_and_issuance(identity):
    _, ca, key, cert = identity
    assert isinstance(key.public_key(), Ed25519PublicKey)
    assert cert.public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    cert.verify_directly_issued_by(ca)
    assert validate_device_certificate(cert, ca, "device-01") == fingerprint(cert)


def test_fingerprint_and_pem_roundtrip(identity):
    cert = identity[3]
    assert fingerprint(cert) == cert.fingerprint(hashes.SHA256()).hex()
    assert len(fingerprint(cert)) == 64
    assert fingerprint(load_certificate(certificate_pem(cert))) == fingerprint(cert)


def test_private_key_storage_is_exclusive(tmp_path, identity):
    import os
    import pytest
    key = identity[2]
    path = tmp_path / "device.key.pem"
    save_private_key(key, path)
    assert load_private_key(path).public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        save_private_key(key, path)
