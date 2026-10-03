"""Offline CA initialization, issuance and certificate registration."""
import argparse
import os
from pathlib import Path

from securemesh.config import Settings
from securemesh.protocol import validate_device_id
from securemesh.security.identity import (IdentityError, certificate_pem, create_ca, generate_private_key,
    issue_device_certificate, issue_server_certificate, load_certificate, load_private_key, save_private_key,
    validate_ca_certificate, write_new_file)
from securemesh.server.main import configure_logging
from securemesh.server.repository import DeviceRepository, RegistryError
from securemesh.server.service import DeviceService


def initialize_ca(settings: Settings, ca_key_path: Path) -> None:
    if ca_key_path.exists() or settings.ca_cert_path.exists():
        raise IdentityError("CA files already exist; refusing to overwrite trust material")
    key = generate_private_key()
    cert = create_ca(key)
    save_private_key(key, ca_key_path)
    write_new_file(settings.ca_cert_path, certificate_pem(cert))


def provision_device(settings: Settings, ca_key_path: Path, device_id: str) -> Path:
    validate_device_id(device_id)
    directory = settings.runtime_dir / "devices" / device_id
    if directory.exists():
        raise IdentityError("Device directory already exists; refusing to replace identity")
    cert = load_certificate(settings.ca_cert_path.read_bytes())
    validate_ca_certificate(cert)
    ca_key = load_private_key(ca_key_path)
    device_key = generate_private_key()
    device_cert = issue_device_certificate(device_id, device_key, ca_key, cert)
    directory.mkdir(parents=True, mode=0o700)
    save_private_key(device_key, directory / "device.key.pem")
    write_new_file(directory / "device.crt.pem", certificate_pem(device_cert))
    return directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--init-ca", action="store_true")
    actions.add_argument("--init-server", action="store_true")
    actions.add_argument("--device-id")
    actions.add_argument("--register-certificate", type=Path)
    actions.add_argument("--revoke-device")
    parser.add_argument("--expected-device-id", help="Required for certificate-only registration")
    args = parser.parse_args()
    configure_logging()
    settings = Settings.from_env()
    # Deliberately only resolve the private-key path in this offline tool.
    ca_key_path = Path(os.getenv("SECUREMESH_CA_KEY_PATH", str(settings.runtime_dir / "ca/ca.key.pem")))
    try:
        if args.init_ca:
            initialize_ca(settings, ca_key_path)
            print(f"CA initialized: {settings.ca_cert_path}")
            return
        if args.init_server:
            if settings.server_key_path.exists() or settings.server_cert_path.exists():
                raise IdentityError("Server identity already exists; refusing to overwrite")
            ca_cert = load_certificate(settings.ca_cert_path.read_bytes())
            key = generate_private_key()
            cert = issue_server_certificate(settings.server_identity, key, load_private_key(ca_key_path), ca_cert)
            save_private_key(key, settings.server_key_path)
            write_new_file(settings.server_cert_path, certificate_pem(cert))
            print(f"Server identity initialized: {settings.server_cert_path}")
            return
        repository = DeviceRepository(settings.database_path)
        repository.initialize()
        service = DeviceService(repository, load_certificate(settings.ca_cert_path.read_bytes()))
        if args.revoke_device:
            service.revoke_device(validate_device_id(args.revoke_device))
            print(f"Revoked: {args.revoke_device}")
        elif args.register_certificate:
            if not args.expected_device_id:
                parser.error("--register-certificate requires --expected-device-id")
            service.register_device(args.expected_device_id, args.register_certificate.read_bytes())
            print(f"Registered: {args.expected_device_id}")
        else:
            if repository.get_device(args.device_id):
                raise RegistryError("Device is already registered")
            directory = provision_device(settings, ca_key_path, args.device_id)
            service.register_device(args.device_id, (directory / "device.crt.pem").read_bytes())
            print(f"Provisioned and registered: {args.device_id} ({directory})")
    except (IdentityError, RegistryError, OSError, ValueError) as exc:
        parser.exit(1, f"Provisioning failed: {exc}\n")


if __name__ == "__main__":
    main()
