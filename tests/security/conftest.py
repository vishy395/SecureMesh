import pytest

from securemesh.security.identity import certificate_pem, generate_private_key, issue_server_certificate
from securemesh.security.sessions import DeviceHandshake, ServerHandshake, now_ms
from securemesh.server.service import TelemetryService


@pytest.fixture
def peers(identity, registry, settings):
    ca_key, ca, device_key, device_cert = identity
    server_key = generate_private_key()
    server_cert = issue_server_certificate(settings.server_identity, server_key, ca_key, ca)
    repository, service = registry
    service.register_device("device-01", certificate_pem(device_cert))
    clock_value = [now_ms()]
    clock = lambda: clock_value[0]
    client = DeviceHandshake(settings, "device-01", device_key, device_cert, ca, server_cert, clock)
    server = ServerHandshake(settings, server_key, server_cert, service.validate_registered_device, clock)
    center = TelemetryService(settings, service, server_key, server_cert, clock)
    return client, server, center, repository, clock_value


@pytest.fixture
def connected(peers):
    from securemesh.security.envelopes import accept_ready
    from securemesh.protocol import canonical_json, handshake_topic, parse_json
    client, _, center, repository, clock = peers
    hello = client.start()
    _, response = center.process_message(handshake_topic("device-01", "hello"), canonical_json(hello))
    finish = client.accept_response(parse_json(response))
    _, ready = center.process_message(handshake_topic("device-01", "finish"), canonical_json(finish))
    accept_ready(client.session, parse_json(ready), now=clock[0])
    return client.session, center.sessions[client.session.session_id], center, repository, clock
