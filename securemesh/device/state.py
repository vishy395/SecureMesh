"""Device identity loading; sessions/counters deliberately do not survive restart."""
from securemesh.config import Settings
from securemesh.protocol import validate_device_id
from securemesh.security.identity import load_certificate, load_private_key, validate_device_certificate
from securemesh.security.sessions import DeviceHandshake


def load_handshake(settings: Settings, device_id: str) -> DeviceHandshake:
    validate_device_id(device_id)
    directory = settings.runtime_dir / "devices" / device_id
    key = load_private_key(directory / "device.key.pem")
    certificate = load_certificate((directory / "device.crt.pem").read_bytes())
    ca = load_certificate(settings.ca_cert_path.read_bytes())
    validate_device_certificate(certificate, ca, device_id)
    server = load_certificate(settings.server_cert_path.read_bytes())
    return DeviceHandshake(settings, device_id, key, certificate, ca, server)
