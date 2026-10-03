import pytest

from securemesh.protocol import MessageType, canonical_json, device_topic, validate_device_id


def test_deterministic_serialization():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"nested": {1: "ambiguous key"}})


@pytest.mark.parametrize("device_id", ["../escape", "a/b", "a+", "a#", "", "a" * 65])
def test_unsafe_device_ids(device_id):
    with pytest.raises(ValueError):
        validate_device_id(device_id)


def test_topic():
    assert device_topic("device-01", MessageType.TELEMETRY) == "securemesh/v1/devices/device-01/telemetry"
