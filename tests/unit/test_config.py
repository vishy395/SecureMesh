import pytest

from securemesh.config import Settings


def test_environment_configuration(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUREMESH_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("SECUREMESH_DATABASE_PATH", str(tmp_path / "custom.db"))
    monkeypatch.setenv("SECUREMESH_CA_CERT_PATH", str(tmp_path / "public.pem"))
    monkeypatch.setenv("SECUREMESH_SERVER_PORT", "8123")
    monkeypatch.setenv("SECUREMESH_MQTT_PORT", "1884")
    monkeypatch.setenv("SECUREMESH_CA_KEY_PATH", "must-not-enter-server-settings.pem")
    config = Settings.from_env()
    assert config.runtime_dir == tmp_path
    assert config.database_path == tmp_path / "custom.db"
    assert config.ca_cert_path == tmp_path / "public.pem"
    assert config.server_port == 8123
    assert config.mqtt_port == 1884
    assert not hasattr(config, "ca_key_path")


def test_invalid_port(monkeypatch):
    monkeypatch.setenv("SECUREMESH_SERVER_PORT", "0")
    with pytest.raises(ValueError):
        Settings.from_env()
