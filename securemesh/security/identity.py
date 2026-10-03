"""Ed25519/X.509 identity profile with a single pinned, offline CA."""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

from securemesh.protocol import validate_device_id


class IdentityError(ValueError):
    """Certificate or key violates the SecureMesh identity profile."""


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def certificate_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def load_certificate(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise IdentityError("Malformed certificate") from exc


def save_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    write_new_file(path, data, private=True)


def write_new_file(path: Path, data: bytes, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents silently replacing an enrolled identity.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise IdentityError("Invalid offline private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError("Expected an Ed25519 private key")
    return key


def create_ca(key: Ed25519PrivateKey, *, now: datetime | None = None) -> x509.Certificate:
    now = now or datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureMesh Development CA")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_usage(ca=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, algorithm=None))


def _usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                        key_encipherment=False, data_encipherment=False, key_agreement=False,
                        key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False)


def _check_profile(cert: x509.Certificate, now: datetime) -> None:
    if not isinstance(cert.public_key(), Ed25519PublicKey) or cert.signature_algorithm_oid != SignatureAlgorithmOID.ED25519:
        raise IdentityError("Certificate must use Ed25519")
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise IdentityError("Certificate is outside its validity period")
    # Unknown critical extensions cannot be safely ignored by this limited profile.
    supported = {x509.ExtensionOID.BASIC_CONSTRAINTS, x509.ExtensionOID.KEY_USAGE,
                 x509.ExtensionOID.EXTENDED_KEY_USAGE, x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
    if any(ext.critical and ext.oid not in supported for ext in cert.extensions):
        raise IdentityError("Unsupported critical certificate extension")


def validate_ca_certificate(cert: x509.Certificate, *, now: datetime | None = None) -> None:
    try:
        _check_profile(cert, now or datetime.now(timezone.utc))
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not constraints.critical or not constraints.value.ca or constraints.value.path_length != 0:
            raise IdentityError("Invalid CA basic constraints")
        if not usage.critical or not usage.value.key_cert_sign:
            raise IdentityError("CA cannot sign certificates")
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, ValueError, x509.ExtensionNotFound) as exc:
        raise IdentityError("Invalid CA certificate") from exc


def issue_device_certificate(device_id: str, device_key: Ed25519PrivateKey,
                             ca_key: Ed25519PrivateKey, ca_cert: x509.Certificate,
                             *, now: datetime | None = None, validity_days: int = 365) -> x509.Certificate:
    validate_device_id(device_id)
    now = now or datetime.now(timezone.utc)
    validate_ca_certificate(ca_cert, now=now)
    if ca_key.public_key().public_bytes_raw() != ca_cert.public_key().public_bytes_raw():
        raise IdentityError("CA key does not match CA certificate")
    if not 1 <= validity_days <= 365:
        raise IdentityError("Device validity must be 1-365 days")
    expiry = min(now + timedelta(days=validity_days), ca_cert.not_valid_after_utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
            .issuer_name(ca_cert.subject).public_key(device_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(max(now - timedelta(minutes=5), ca_cert.not_valid_before_utc))
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_usage(ca=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                f"urn:securemesh:device:{device_id}")]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(device_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, algorithm=None))


def validate_device_certificate(cert: x509.Certificate, ca_cert: x509.Certificate,
                                device_id: str, *, expected_fingerprint: str | None = None,
                                now: datetime | None = None) -> str:
    """Validate issuance, identity and optionally the registry's pinned fingerprint.

    Enrollment omits the fingerprint; runtime validation must supply the stored pin.
    """
    try:
        validate_device_id(device_id)
        now = now or datetime.now(timezone.utc)
        validate_ca_certificate(ca_cert, now=now)
        _check_profile(cert, now)
        cert.verify_directly_issued_by(ca_cert)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if len(cn) != 1 or cn[0].value != device_id or san.get_values_for_type(x509.UniformResourceIdentifier) != [f"urn:securemesh:device:{device_id}"]:
            raise IdentityError("Device ID does not match signed certificate identity")
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if not constraints.critical or constraints.value.ca or not usage.critical or not usage.value.digital_signature or usage.value.key_cert_sign or usage.value.key_agreement:
            raise IdentityError("Invalid device certificate usage")
        if set(eku) != {ExtendedKeyUsageOID.CLIENT_AUTH}:
            raise IdentityError("Invalid device extended key usage")
        if cert.not_valid_before_utc < ca_cert.not_valid_before_utc or cert.not_valid_after_utc > ca_cert.not_valid_after_utc:
            raise IdentityError("Device validity exceeds CA validity")
        result = fingerprint(cert)
        if expected_fingerprint is not None and result != expected_fingerprint:
            raise IdentityError("Certificate fingerprint does not match registered identity")
        return result
    except (InvalidSignature, ValueError, x509.ExtensionNotFound) as exc:
        raise IdentityError(f"Device certificate rejected: {exc}" if isinstance(exc, IdentityError)
                            else "Device certificate rejected") from exc
