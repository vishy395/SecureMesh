# Stage 2 validation

Validated on 3 October 2026, Windows, Python 3.12.2, cryptography 46.0.7, Paho MQTT 2.1.0 and Mosquitto 2.1.2.

## Commands executed

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m scripts.provision --init-server
.\.venv\Scripts\python.exe -m scripts.setup_broker --password-tool .\runtime\tools\mosquitto\mosquitto_passwd.exe
.\.venv\Scripts\python.exe -m pytest tests/integration/test_mqtt_telemetry.py -v -s
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
```

The original Stage 1 CA, registry and three device identities were preserved. Mosquitto's official Windows package was extracted into ignored `runtime/tools/mosquitto`; no system service was installed. A separate persistent demonstration started that broker, the FastAPI server and the original provisioned `device-01`, using `--interval 0.1 --count 12`. An observer captured a protected envelope and republished it.

## Observed results

- Original Stage 1 tests plus Stage 2 tests: **100 passed**; no skipped live test.
- One upstream Starlette TestClient/httpx deprecation warning; no test failures.
- `pip check`: no broken requirements.
- Live integration: successful mutual authentication, 12 accepted/decrypted/stored readings, receive sequence 12, last_seen updated.
- Persistent project demonstration: original `device-01` authenticated, 12 readings persisted, captured replay rejected, row count and receive sequence unchanged.
- Captured MQTT fields: ciphertext, device_id, direction, message_type, nonce, sequence, session_id, version. No plaintext temperature/battery/CPU values in the MQTT payload.
- Persistent security events include `session_authenticated` and `replay_attempt`.

## Security review

- Fresh X25519 keys/challenges on every handshake attempt; ephemeral references dropped after derivation or expiry.
- HKDF binds the entire transcript with independently labeled directional AES keys.
- Both peers sign the full canonical transcript with different role labels. Devices additionally pin the server certificate; a device certificate cannot serve as a server identity.
- Version 1 is mandatory; no downgrade fallback.
- Six security headers are AES-GCM associated data. Nonce is checked against the deterministic 4-byte prefix + 8-byte counter construction.
- Send counters are locked and burned before encryption; failures never reset a counter under the same key.
- Receive counters change only after tag/schema/freshness validation and a successful atomic SQLite transaction. Forged sequence 500 and transaction failure cannot poison replay state.
- Database writes explicitly enumerate session metadata; no session keys are serialized. Session key fields are omitted from object representations.
- Events/logs use fixed codes and selected IDs/sequences, with no raw keys, secrets or telemetry values.
- Server restart invalidates session metadata; old session keys cannot be recovered/resumed.

This review and test suite support an educational Stage 2 implementation, not a production security audit. Remaining limitations are documented in `threat-model.md`. Commands, dashboard, attack runner, identity rotation and full revocation workflow were not implemented.
