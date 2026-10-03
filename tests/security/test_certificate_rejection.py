from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization

from securemesh.security.identity import (IdentityError, certificate_pem, create_ca, generate_private_key,
    issue_device_certificate, load_certificate, validate_ca_certificate, validate_device_certificate)


def test_modified_certificate_rejected(identity):
    _, ca, _, cert = identity
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    from cryptography import x509
    modified = x509.load_der_x509_certificate(bytes(der))
    with pytest.raises(IdentityError):
        validate_device_certificate(modified, ca, "device-01")


def test_malformed_certificate_rejected():
    with pytest.raises(IdentityError):
        load_certificate(b"not a certificate")


def test_wrong_ca_rejected(identity):
    _, _, _, cert = identity
    other_ca = create_ca(generate_private_key())
    with pytest.raises(IdentityError):
        validate_device_certificate(cert, other_ca, "device-01")


def test_expired_device_rejected(identity):
    _, ca, _, cert = identity
    with pytest.raises(IdentityError):
        validate_device_certificate(cert, ca, "device-01", now=cert.not_valid_after_utc + timedelta(seconds=1))


def test_not_yet_valid_device_rejected(identity):
    ca_key, ca, key, _ = identity
    cert = issue_device_certificate("device-01", key, ca_key, ca,
                                    now=ca.not_valid_before_utc + timedelta(days=2))
    with pytest.raises(IdentityError):
        validate_device_certificate(cert, ca, "device-01", now=ca.not_valid_before_utc + timedelta(days=1))


def test_expired_ca_rejected(identity):
    ca = identity[1]
    with pytest.raises(IdentityError):
        validate_ca_certificate(ca, now=ca.not_valid_after_utc + timedelta(seconds=1))


def test_device_id_mismatch_rejected(identity):
    with pytest.raises(IdentityError):
        validate_device_certificate(identity[3], identity[1], "device-02")


def test_unknown_device_rejected(registry, identity):
    with pytest.raises(IdentityError, match="Unknown device"):
        registry[1].validate_registered_device("device-01", certificate_pem(identity[3]))


def test_fingerprint_mismatch_rejected(registry, identity):
    ca_key, ca, _, cert = identity
    service = registry[1]
    service.register_device("device-01", certificate_pem(cert))
    replacement = issue_device_certificate("device-01", generate_private_key(), ca_key, ca)
    with pytest.raises(IdentityError, match="fingerprint"):
        service.validate_registered_device("device-01", certificate_pem(replacement))


def test_registered_and_revoked_identity(registry, identity):
    service = registry[1]
    pem = certificate_pem(identity[3])
    service.register_device("device-01", pem)
    assert service.validate_registered_device("device-01", pem)
    service.revoke_device("device-01")
    with pytest.raises(IdentityError, match="revoked"):
        service.validate_registered_device("device-01", pem)


def test_ca_key_mismatch_rejected(identity):
    with pytest.raises(IdentityError, match="CA key"):
        issue_device_certificate("device-01", identity[2], generate_private_key(), identity[1])


def test_rejected_registration_does_not_mutate_database(registry, identity):
    repository, service = registry
    with pytest.raises(IdentityError):
        service.register_device("device-02", certificate_pem(identity[3]))
    assert repository.list_devices() == []
