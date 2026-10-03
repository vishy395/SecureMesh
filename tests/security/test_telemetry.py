from concurrent.futures import ThreadPoolExecutor

import pytest

from securemesh.device.telemetry import generate_telemetry
from securemesh.protocol import canonical_json, encode_bytes, parse_json
from securemesh.security.envelopes import encrypt_message, nonce_for_sequence
from securemesh.security.sessions import SecurityError
from securemesh.server.service import TelemetryService


def make_envelope(connected, timestamp=None):
    payload = generate_telemetry()
    payload["timestamp"] = connected[4][0] if timestamp is None else timestamp
    return encrypt_message(connected[0], payload, "telemetry", now=connected[4][0])


def test_first_telemetry_and_atomic_persistence(connected):
    device, server, center, repository, _ = connected
    center.accept_telemetry("device-01", make_envelope(connected))
    assert server.receive_sequence == 1
    assert repository.list_sessions()[0]["receive_sequence"] == 1
    assert repository.list_telemetry()[0]["sequence"] == 1
    assert repository.get_device("device-01")["last_seen"] is not None


def test_duplicate_and_lower_sequence_rejected(connected):
    _, server, center, repository, _ = connected
    first, second = make_envelope(connected), make_envelope(connected)
    center.accept_telemetry("device-01", second)
    for envelope in (second, first):
        with pytest.raises(SecurityError, match="replay_attempt"):
            center.accept_telemetry("device-01", envelope)
    assert server.receive_sequence == 2
    assert len(repository.list_telemetry()) == 1


def test_forged_high_sequence_does_not_advance_state(connected):
    _, server, center, repository, _ = connected
    legit = make_envelope(connected)
    forged = dict(legit, sequence=500, nonce=encode_bytes(nonce_for_sequence(server.device_nonce_prefix, 500)))
    with pytest.raises(SecurityError, match="invalid_authentication_tag"):
        center.accept_telemetry("device-01", forged)
    assert server.receive_sequence == repository.list_sessions()[0]["receive_sequence"] == 0
    assert repository.list_telemetry() == []
    center.accept_telemetry("device-01", legit)
    assert server.receive_sequence == 1


@pytest.mark.parametrize("sequence", [0, -1, True, 1.0, "1", 100001, 2**64])
def test_invalid_sequence(connected, sequence):
    envelope = make_envelope(connected)
    envelope["sequence"] = sequence
    with pytest.raises(SecurityError, match="invalid_sequence"):
        connected[2].accept_telemetry("device-01", envelope)
    assert connected[1].receive_sequence == 0


@pytest.mark.parametrize("offset", [-31000, 6000])
def test_stale_or_future_timestamp(connected, offset):
    envelope = make_envelope(connected, connected[4][0] + offset)
    with pytest.raises(SecurityError, match="stale_message"):
        connected[2].accept_telemetry("device-01", envelope)
    assert connected[1].receive_sequence == 0
    assert connected[3].list_telemetry() == []


def test_expired_session(connected):
    envelope = make_envelope(connected)
    connected[4][0] = connected[1].expires_at
    with pytest.raises(SecurityError, match="expired_session"):
        connected[2].accept_telemetry("device-01", envelope)


def test_freshness_failure_does_not_poison_replay(connected):
    first = make_envelope(connected)
    second = make_envelope(connected, connected[4][0] - 31000)
    with pytest.raises(SecurityError, match="stale_message"):
        connected[2].accept_telemetry("device-01", second)
    connected[2].accept_telemetry("device-01", first)
    assert connected[1].receive_sequence == 1


def test_concurrent_duplicate_commits_once(connected):
    envelope = make_envelope(connected)

    def accept(_):
        try:
            connected[2].accept_telemetry("device-01", envelope)
            return True
        except SecurityError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(accept, range(4))) == 1
    assert len(connected[3].list_telemetry()) == 1


def test_database_failure_does_not_advance_memory(connected, monkeypatch):
    from securemesh.server.repository import RegistryError
    original = connected[3].store_telemetry

    def fail(*args):
        raise RegistryError("simulated transaction failure")

    monkeypatch.setattr(connected[3], "store_telemetry", fail)
    envelope = make_envelope(connected)
    with pytest.raises(SecurityError, match="session_state_conflict"):
        connected[2].accept_telemetry("device-01", envelope)
    assert connected[1].receive_sequence == connected[3].list_sessions()[0]["receive_sequence"] == 0
    monkeypatch.setattr(connected[3], "store_telemetry", original)
    connected[2].accept_telemetry("device-01", envelope)


def test_session_keys_not_persisted_or_in_repr(connected):
    device, server, _, repository, _ = connected
    with repository._connection() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(sessions)")}
    assert not any("key" in column or "secret" in column for column in columns)
    data = repository.database_path.read_bytes()
    for key in (device.device_to_server_key, device.server_to_device_key):
        assert key not in data
        assert key.hex() not in repr(server)
        assert repr(key) not in repr(server)


def test_server_restart_invalidates_sessions(connected):
    _, _, center, repository, clock = connected
    envelope = make_envelope(connected)
    restarted = TelemetryService(center.settings, center.registry, center.handshake.key,
                                 center.handshake.certificate, lambda: clock[0])
    assert not restarted.sessions
    assert repository.list_sessions()[0]["active"] == 0
    with pytest.raises(SecurityError, match="invalid_session"):
        restarted.accept_telemetry("device-01", envelope)


def test_security_events_and_no_payload_logging(connected, caplog):
    envelope = make_envelope(connected)
    topic = "securemesh/v1/devices/device-01/telemetry"
    connected[2].process_message(topic, canonical_json(envelope))
    connected[2].process_message(topic, canonical_json(envelope))
    assert connected[3].list_security_events()[0]["event_type"] == "replay_attempt"
    assert "temperature" not in caplog.text
    assert envelope["ciphertext"] not in caplog.text


def test_revoked_device_rejected(connected):
    envelope = make_envelope(connected)
    connected[2].registry.revoke_device("device-01")
    with pytest.raises(SecurityError, match="revoked_device"):
        connected[2].accept_telemetry("device-01", envelope)


def test_strict_wire_parser():
    for payload in (b'{"version":1,"version":2}', b'{"value":NaN}', b'{"value":1e999}', b'[]'):
        with pytest.raises(ValueError):
            parse_json(payload)


def test_retained_and_topic_identity_mismatch(connected):
    envelope = make_envelope(connected)
    topic = "securemesh/v1/devices/device-01/telemetry"
    connected[2].process_message(topic, canonical_json(envelope), retained=True)
    assert connected[3].list_security_events()[0]["event_type"] == "retained_message_rejected"
    assert connected[1].receive_sequence == 0


def test_sqlite_transaction_rolls_back_replay_update(connected):
    _, server, center, repository, clock = connected
    # The INSERT serialization fails after the SQL sequence update; rollback must undo it.
    with pytest.raises(ValueError):
        repository.store_telemetry(server.session_id, "device-01", 500,
            {"timestamp": clock[0], "value": float("nan")}, clock[0])
    assert repository.list_sessions()[0]["receive_sequence"] == 0
    assert repository.list_telemetry() == []
    assert repository.get_device("device-01")["last_seen"] is None
    center.accept_telemetry("device-01", make_envelope(connected))
    assert server.receive_sequence == 1


@pytest.mark.parametrize("offset", [-30000, 5000])
def test_freshness_window_boundaries(connected, offset):
    connected[2].accept_telemetry("device-01", make_envelope(connected, connected[4][0] + offset))
    assert connected[1].receive_sequence == 1


def test_expiry_cleanup_invalidates_metadata(connected):
    connected[4][0] = connected[1].expires_at
    connected[2].prune()
    assert not connected[2].sessions
    assert connected[3].list_sessions()[0]["active"] == 0


def test_invalid_telemetry_does_not_advance_state(connected):
    payload = generate_telemetry()
    payload["battery"] = 500
    envelope = encrypt_message(connected[0], payload, "telemetry", now=connected[4][0])
    with pytest.raises(SecurityError, match="invalid_telemetry"):
        connected[2].accept_telemetry("device-01", envelope)
    assert connected[1].receive_sequence == 0
