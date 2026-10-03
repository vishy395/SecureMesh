from concurrent.futures import ThreadPoolExecutor

import pytest

from securemesh.protocol import decode_bytes, encode_bytes
from securemesh.security.envelopes import decrypt_message, encrypt_message, nonce_for_sequence
from securemesh.security.sessions import SecurityError


def test_valid_encryption_and_no_receive_mutation(connected):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {"secret": "reading"}, "telemetry", now=clock[0])
    assert "reading" not in str(envelope)
    assert decrypt_message(server, envelope, "telemetry", now=clock[0]) == {"secret": "reading"}
    assert server.receive_sequence == 0


def test_modified_ciphertext(connected):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {}, "telemetry", now=clock[0])
    ciphertext = bytearray(decode_bytes(envelope["ciphertext"]))
    ciphertext[0] ^= 1
    envelope["ciphertext"] = encode_bytes(bytes(ciphertext))
    with pytest.raises(SecurityError, match="invalid_authentication_tag"):
        decrypt_message(server, envelope, "telemetry", now=clock[0])


def test_modified_associated_data(connected):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {}, "telemetry", now=clock[0])
    envelope["sequence"] = 2
    envelope["nonce"] = encode_bytes(nonce_for_sequence(server.device_nonce_prefix, 2))
    with pytest.raises(SecurityError, match="invalid_authentication_tag"):
        decrypt_message(server, envelope, "telemetry", now=clock[0])


def test_wrong_key(connected):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {}, "telemetry", now=clock[0])
    server.device_to_server_key = bytes(32)
    with pytest.raises(SecurityError, match="invalid_authentication_tag"):
        decrypt_message(server, envelope, "telemetry", now=clock[0])


@pytest.mark.parametrize("field,value,event", [("direction", "server_to_device", "wrong_direction"),
    ("version", 0, "protocol_version_mismatch"), ("device_id", "device-02", "invalid_session"),
    ("session_id", "f" * 32, "invalid_session"), ("message_type", "commands", "invalid_message_type")])
def test_header_rejections(connected, field, value, event):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {}, "telemetry", now=clock[0])
    envelope[field] = value
    with pytest.raises(SecurityError, match=event):
        decrypt_message(server, envelope, "telemetry", now=clock[0])
    assert server.receive_sequence == 0


def test_nonce_uniqueness_and_concurrent_counter_reservation(connected):
    device, _, _, _, clock = connected
    with ThreadPoolExecutor(max_workers=8) as pool:
        envelopes = list(pool.map(lambda _: encrypt_message(device, {}, "telemetry", now=clock[0]), range(100)))
    assert len({envelope["nonce"] for envelope in envelopes}) == 100
    assert sorted(envelope["sequence"] for envelope in envelopes) == list(range(1, 101))
    for envelope in envelopes:
        assert decode_bytes(envelope["nonce"]) == nonce_for_sequence(device.device_nonce_prefix, envelope["sequence"])
    assert nonce_for_sequence(b"abcd", 1) == b"abcd" + (1).to_bytes(8, "big")


def test_counter_is_burned_on_encryption_failure(connected):
    device, _, _, _, clock = connected
    with pytest.raises(ValueError):
        encrypt_message(device, {"bad": float("nan")}, "telemetry", now=clock[0])
    assert encrypt_message(device, {}, "telemetry", now=clock[0])["sequence"] == 2


def test_message_limit(connected):
    device, _, _, _, clock = connected
    device.send_sequence = device.max_messages
    with pytest.raises(SecurityError, match="session_message_limit"):
        encrypt_message(device, {}, "telemetry", now=clock[0])


def test_modified_nonce(connected):
    device, server, _, _, clock = connected
    envelope = encrypt_message(device, {}, "telemetry", now=clock[0])
    envelope["nonce"] = encode_bytes(bytes(12))
    with pytest.raises(SecurityError, match="invalid_nonce"):
        decrypt_message(server, envelope, "telemetry", now=clock[0])
