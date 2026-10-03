import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from securemesh.protocol import canonical_json, encode_bytes, handshake_topic
from securemesh.security.envelopes import accept_ready, encrypt_message
from securemesh.security.identity import (IdentityError, certificate_pem, fingerprint, generate_private_key,
                                         issue_device_certificate, issue_server_certificate)
from securemesh.security.sessions import SecurityError, derive_material


def exchange(peers):
    client, server, _, _, _ = peers
    hello = client.start()
    response = server.accept_hello(hello, "device-01")
    finish = client.accept_response(response)
    session = server.accept_finish(finish, "device-01")
    ready = encrypt_message(session, {"session_id": session.session_id,
        "transcript_hash": session.transcript_hash, "status": "ready"}, "handshake_ready", now=peers[4][0])
    accept_ready(client.session, ready, now=peers[4][0])
    return hello, response, finish, session


def test_valid_mutual_handshake_and_directional_keys(peers):
    _, _, _, server = exchange(peers)
    device = peers[0].session
    assert server.authenticated and device.authenticated
    assert server.device_to_server_key == device.device_to_server_key
    assert server.server_to_device_key == device.server_to_device_key
    assert server.device_to_server_key != server.server_to_device_key
    assert len(server.device_to_server_key) == len(server.server_to_device_key) == 32
    assert peers[0].ephemeral is None
    assert not peers[1].pending


def test_unknown_device(peers, identity):
    client, _, center, repository, _ = peers
    certificate = issue_device_certificate("unknown", client.key, identity[0], identity[1])
    client.device_id, client.certificate = "unknown", certificate
    assert center.process_message(handshake_topic("unknown", "hello"), canonical_json(client.start())) is None
    assert "unknown_device" in {event["event_type"] for event in repository.list_security_events()}
    assert not center.sessions


def test_modified_device_certificate(peers):
    client, server, _, _, _ = peers
    hello = client.start()
    der = bytearray(client.certificate.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    hello["certificate"] = certificate_pem(x509.load_der_x509_certificate(bytes(der))).decode()
    with pytest.raises(IdentityError):
        server.accept_hello(hello, "device-01")


def test_invalid_device_hello_signature(peers):
    hello = peers[0].start()
    hello["signature"] = encode_bytes(bytes(64))
    with pytest.raises(SecurityError, match="invalid_signature"):
        peers[1].accept_hello(hello, "device-01")


def test_invalid_device_finish_signature(peers):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    finish = client.accept_response(response)
    finish["signature"] = encode_bytes(bytes(64))
    with pytest.raises(SecurityError, match="invalid_signature"):
        server.accept_finish(finish, "device-01")


def test_invalid_server_signature(peers):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    response["signature"] = encode_bytes(bytes(64))
    with pytest.raises(SecurityError, match="invalid_signature"):
        client.accept_response(response)
    assert client.session is None


@pytest.mark.parametrize("field,value", [("server_ephemeral", encode_bytes(X25519PrivateKey.generate().public_key().public_bytes_raw())),
    ("server_challenge", encode_bytes(bytes(32))), ("expires_at", 1), ("max_messages", 1), ("session_id", "a" * 32)])
def test_modified_server_transcript(peers, field, value):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    response[field] = value
    with pytest.raises(SecurityError, match="invalid_signature"):
        client.accept_response(response)


def test_modified_device_ephemeral(peers):
    hello = peers[0].start()
    hello["device_ephemeral"] = encode_bytes(X25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(SecurityError, match="invalid_signature"):
        peers[1].accept_hello(hello, "device-01")


def test_replayed_challenge_and_finish(peers):
    hello, _, finish, _ = exchange(peers)
    with pytest.raises(SecurityError, match="replayed_challenge"):
        peers[1].accept_hello(hello, "device-01")
    with pytest.raises(SecurityError, match="invalid_session"):
        peers[1].accept_finish(finish, "device-01")


def test_expired_hello_and_finish(peers):
    client, server = peers[:2]
    hello = client.start()
    response = server.accept_hello(hello, "device-01")
    finish = client.accept_response(response)
    peers[4][0] += 16000
    with pytest.raises(SecurityError, match="expired_challenge"):
        server.accept_finish(finish, "device-01")
    with pytest.raises(SecurityError, match="expired_challenge"):
        server.accept_hello(hello, "device-01")


def test_expired_response(peers):
    response = peers[1].accept_hello(peers[0].start(), "device-01")
    peers[4][0] += 16000
    with pytest.raises(SecurityError, match="expired_challenge"):
        peers[0].accept_response(response)


@pytest.mark.parametrize("version", [0, 2, True, "1"])
def test_version_mismatch(peers, version):
    hello = peers[0].start()
    hello["version"] = version
    with pytest.raises(SecurityError, match="protocol_version_mismatch"):
        peers[1].accept_hello(hello, "device-01")


def test_x25519_agreement_and_hkdf():
    device, server = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    dshared = device.exchange(server.public_key())
    sshared = server.exchange(device.public_key())
    assert dshared == sshared
    assert derive_material(dshared, b"bound transcript") == derive_material(sshared, b"bound transcript")
    assert derive_material(dshared, b"bound transcript") != derive_material(dshared, b"other transcript")


def test_fresh_ephemeral_keys_and_session_keys(peers):
    hello1, response1, _, session1 = exchange(peers)
    hello2, response2, _, session2 = exchange(peers)
    assert hello1["device_ephemeral"] != hello2["device_ephemeral"]
    assert response1["server_ephemeral"] != response2["server_ephemeral"]
    assert session1.session_id != session2.session_id
    assert session1.device_to_server_key != session2.device_to_server_key


def test_device_certificate_cannot_act_as_server(peers, identity):
    from securemesh.security.identity import validate_server_certificate
    with pytest.raises(IdentityError):
        validate_server_certificate(identity[3], identity[1], "device-01")


def test_other_valid_server_certificate_rejected_by_pin(peers, identity):
    client, server = peers[:2]
    other_key = generate_private_key()
    other_cert = issue_server_certificate("control-center", other_key, identity[0], identity[1])
    response = server.accept_hello(client.start(), "device-01")
    response["certificate"] = certificate_pem(other_cert).decode()
    response["server_fingerprint"] = fingerprint(other_cert)
    with pytest.raises(IdentityError):
        client.accept_response(response)


def test_no_authentication_before_encrypted_ready(peers):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    finish = client.accept_response(response)
    assert not client.session.authenticated
    with pytest.raises(SecurityError, match="invalid_session"):
        encrypt_message(client.session, {}, "telemetry", now=peers[4][0])
    server.accept_finish(finish, "device-01")


def test_cross_session_response_rejected(peers):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    client.start()
    with pytest.raises(SecurityError, match="invalid_signature"):
        client.accept_response(response)


def test_modified_finish_transcript_hash(peers):
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    finish = client.accept_response(response)
    finish["transcript_hash"] = "0" * 64
    with pytest.raises(SecurityError, match="transcript_mismatch"):
        server.accept_finish(finish, "device-01")


def test_null_x25519_shared_secret_rejected(peers):
    from securemesh.security.sessions import transcript_bytes
    client, server = peers[:2]
    response = server.accept_hello(client.start(), "device-01")
    response["server_ephemeral"] = encode_bytes(bytes(32))
    transcript = transcript_bytes(client.hello, response)
    response["signature"] = encode_bytes(server.key.sign(b"SecureMesh/v1/server-response\x00" + transcript))
    with pytest.raises(SecurityError, match="invalid_ephemeral_key"):
        client.accept_response(response)


def test_unauthenticated_hello_does_not_consume_challenge(peers):
    client, server = peers[:2]
    original = client.start()
    forged = dict(original, signature=encode_bytes(bytes(64)))
    with pytest.raises(SecurityError):
        server.accept_hello(forged, "device-01")
    assert server.accept_hello(original, "device-01")


def test_device_cannot_authenticate_on_another_topic(peers):
    hello = peers[0].start()
    with pytest.raises(SecurityError, match="identity_mismatch"):
        peers[1].accept_hello(hello, "device-02")
