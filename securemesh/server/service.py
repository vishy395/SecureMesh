"""Certificate admission and registry policy; repository handles persistence."""
import logging

from cryptography import x509

from securemesh.security.identity import IdentityError, load_certificate, validate_device_certificate
from securemesh.server.repository import DeviceRepository, RegistryError

logger = logging.getLogger("securemesh.registry")


class DeviceService:
    def __init__(self, repository: DeviceRepository, ca_certificate: x509.Certificate):
        self.repository = repository
        self.ca_certificate = ca_certificate

    def register_device(self, device_id: str, certificate: bytes) -> dict:
        try:
            cert = load_certificate(certificate)
            pin = validate_device_certificate(cert, self.ca_certificate, device_id)
            device = self.repository.register_device(device_id, pin, certificate.decode("ascii"))
        except (IdentityError, RegistryError):
            logger.warning("device_registration_rejected")
            raise
        logger.info("device_registered", extra={"device_id": device_id})
        return device

    def validate_registered_device(self, device_id: str, certificate: bytes) -> str:
        try:
            device = self.repository.get_device(device_id)
            if device is None:
                raise IdentityError("Unknown device")
            if device["revoked_at"] is not None or device["status"] == "revoked":
                raise IdentityError("Device is revoked")
            return validate_device_certificate(load_certificate(certificate), self.ca_certificate,
                                               device_id, expected_fingerprint=device["certificate_fingerprint"])
        except IdentityError:
            logger.warning("device_identity_rejected")
            raise

    def list_devices(self) -> list[dict]:
        # Public registry metadata only; certificate PEM stays in local storage.
        return [{k: v for k, v in device.items() if k != "certificate"}
                for device in self.repository.list_devices()]

    def revoke_device(self, device_id: str) -> None:
        self.repository.revoke_device(device_id)
        logger.info("device_revoked", extra={"device_id": device_id})
