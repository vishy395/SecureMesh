# SecureMesh

Cryptographic Command & Telemetry Network for IoT Devices, a college cyber defense project. All devices are Python simulators; no physical hardware is required.

**Stages 1?3 are implemented:** offline CA, Ed25519/X.509 identities, SQLite registry, mutual authentication, ephemeral X25519 sessions, directional HKDF keys, AES-256-GCM telemetry and commands, authenticated acknowledgements, durable command deduplication, device lifecycle, revocation and session rotation. Dashboard, attack simulator and long-term identity rotation remain future work.

## Architecture

`offline provisioning → CA-signed device certificate → validated SQLite registration`

`FastAPI → service policy → repository → SQLite`

`simulator → signed handshake → MQTT → control center → authenticated decryption → SQLite`

Cryptographic operations live in `securemesh/security/`. The server loads the public CA certificate and its own server identity key, never the CA private key. The offline tool alone loads the CA private key. Device private keys live under `runtime/devices/<device-id>/`, never in SQLite. Sessions contain only in-memory keys; SQLite stores metadata, telemetry and sanitized security events.

**CA → Device Certificate → Device Identity:** the trusted CA signs a binding between a device ID and an Ed25519 public key. The registry pins the certificate's SHA-256 fingerprint. A certificate alone does not prove possession of its private key; signed handshake messages provide that proof. Devices also validate and pin a distinct CA-signed server certificate with the server-authentication role.

MQTT credentials authorize broker access. They do not establish end-to-end device identity: a compromised broker could publish messages or mislabel topics. SecureMesh independently validates identities, handshake signatures and encrypted envelopes. MQTT exposes public certificates and routing metadata, but never plaintext telemetry.

## Installation and manual verification (PowerShell)

Install Python 3.11 or newer, then run these commands from the repository root. If `python` opens the Microsoft Store, use the absolute path to your installed Python interpreter for the first command.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m scripts.provision --init-ca
.\.venv\Scripts\python.exe -m scripts.provision --device-id device-01
.\.venv\Scripts\python.exe -m scripts.provision --device-id device-02
.\.venv\Scripts\python.exe -m scripts.provision --device-id device-03
.\.venv\Scripts\python.exe -m scripts.provision --init-server
```

For an existing Stage 1 checkout, keep the CA and device files; run only `--init-server` once. Do not overwrite existing `.env` files. Install [Mosquitto from its official distribution](https://mosquitto.org/download/), or use the project-local copy already unpacked for this workspace's validation. Set the executable paths accordingly:

```powershell
$broker = '.\runtime\tools\mosquitto\mosquitto.exe'
$passwd = '.\runtime\tools\mosquitto\mosquitto_passwd.exe'
.\.venv\Scripts\python.exe -m scripts.setup_broker --password-tool $passwd
& $broker -c .\runtime\mqtt\mosquitto.conf
```

`setup_broker` is one-time setup: it creates random broker credentials, hashes the broker password file and stores client credentials in ignored `runtime/mqtt/client.env`. It never prints the password or passes it in subprocess arguments. If Mosquitto is installed system-wide, use the executable paths in that installation instead. No Mosquitto system service is required.

In a second terminal:

```powershell
$env:SECUREMESH_MQTT_ENABLED='true'
.\.venv\Scripts\python.exe -m securemesh.server.main
```

In a third terminal:

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-01 --interval 2
```

In a fourth terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/devices | Format-Table
Invoke-RestMethod http://127.0.0.1:8000/api/telemetry
Invoke-RestMethod http://127.0.0.1:8000/api/sessions | Format-Table
Invoke-RestMethod http://127.0.0.1:8000/api/security-events | Format-Table
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
```

Stop each process with Ctrl+C. `--count 12 --interval 0.1` runs a finite simulator demonstration. Initialization/provisioning refuse to overwrite identities; on subsequent runs skip setup. `last_seen` updates after accepted telemetry. `registered` is enrollment state, not online state.

The live automated test starts its own Mosquitto, FastAPI and device subprocesses using temporary identities and free loopback ports, accepts 12 encrypted readings, captures an MQTT envelope and republishes it. It verifies a persistent `replay_attempt` event, unchanged row count and receive sequence 12:

```powershell
$env:SECUREMESH_MOSQUITTO_EXE=(Resolve-Path .\runtime\tools\mosquitto\mosquitto.exe).Path
.\.venv\Scripts\python.exe -m pytest tests/integration/test_mqtt_telemetry.py -v -s
```

Without an available Mosquitto executable this test explicitly skips; the security/unit tests still run. It must pass, rather than skip, for full Stage 2 validation.

Optional offline administrative operations:

```powershell
.\.venv\Scripts\python.exe -m scripts.provision --register-certificate runtime/devices/device-01/device.crt.pem --expected-device-id device-01
.\.venv\Scripts\python.exe -m scripts.provision --revoke-device device-03
```

Certificate-only registration is for a previously unregistered identity; duplicates are rejected. Revocation invalidates session metadata and is enforced during handshake, telemetry, commands and acknowledgements. CRLs and device-side revocation distribution remain deferred. If provisioning creates files but registration fails, repair registration with `--register-certificate`; do not replace the key automatically.

## Configuration and security limits

Copy `.env.example` to `.env` on a fresh checkout and change paths/ports as needed. Relative paths resolve against the working directory. Runtime contents and `.env` are ignored by Git. `SECUREMESH_MQTT_ENABLED=true` enables telemetry, commands and acknowledgements; the default without configuration is false so registry-only startup remains available. Loopback Mosquitto requires credentials. Environment variables override both `.env` and the generated client credential file.

Replay policy is fixed to `strict_monotonic`: sequence numbers must exceed the last accepted number; gaps are allowed, duplicates/reordering are rejected. Defaults: session lifetime 600 seconds, handshake lifetime 15 seconds, telemetry maximum age 30 seconds, future clock skew 5 seconds, session message limit 100,000. Counters are never reset within a key lifetime. Session expiration or broker reconnection requires a fresh handshake, not identity rotation. After a control-center restart, old sessions are rejected; restart the simulator for immediate recovery, or wait for its local session expiration.

Keys use exclusive file creation and POSIX mode 0600 where supported; device directories use mode 0700. On Windows, permissions inherit filesystem ACLs: protect `runtime` with account-specific ACLs. Keys are unencrypted development PEM files, so file access controls and a trusted laptop are essential. The CA directory must never be distributed to devices.

The API defaults to loopback and has no administrator login. Stage 3 mutation endpoints assume a trusted local operator. It exposes decrypted telemetry for the trusted local operator; do not expose it to an untrusted network. Logs contain fixed event names and selected IDs/sequences, never key material or telemetry values. Plain MQTT broker credentials and traffic metadata are observable on the transport; application cryptography still protects telemetry and identity. This is an educational protocol, not an independently audited production system. Availability against message dropping/flooding, compromised endpoints and long-term identity rotation are outside this stage.

Certificate validation uses the cryptography library's signature checks plus explicit SecureMesh identity-profile checks; signature verification alone is insufficient. Reference: [cryptography X.509 documentation](https://cryptography.io/en/latest/x509/reference/).


## Stage 3 demonstration (PowerShell)

The isolated automated demonstration is the quickest reproducible option. It creates temporary CA/server/device identities and a temporary SQLite database, launches **real Mosquitto, FastAPI and all three simulator processes**, exercises the demo helper below, and cleans up its processes. It does not revoke your existing registrations:

```powershell
$env:SECUREMESH_MOSQUITTO_EXE=(Resolve-Path .\runtime\tools\mosquitto\mosquitto.exe).Path
.\.venv\Scripts\python.exe -m pytest tests/integration/test_mqtt_commands.py -v -s
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
```

The test must pass without skipping for complete live validation. It verifies all three authenticate/send telemetry, START for device-01, CHANGE_THRESHOLD for device-02, STOP for device-03, encrypted acknowledgements, two exact MQTT redeliveries with one durable execution, restart and explicit session rotation, device-02 revocation and continued operation of device-01/device-03. The broker executable is discovered automatically at the project-local path when available.

For a manual demonstration, use the installation/provisioning/broker setup commands above with **disposable, ACTIVE registrations**. This demonstration permanently revokes device-02; it does not reactivate identities. Keep an existing Stage 2 checkpoint and its identities intact. For repeatable runs, use the isolated automated test rather than overwriting registrations.

Terminal 1, broker:

```powershell
& .\runtime\tools\mosquitto\mosquitto.exe -c .\runtime\mqtt\mosquitto.conf
```

Terminal 2, FastAPI:

```powershell
$env:SECUREMESH_MQTT_ENABLED='true'
.\.venv\Scripts\python.exe -m securemesh.server.main
```

Terminals 3, 4 and 5, one simulator per terminal:

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-01 --interval 1
```

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-02 --interval 1
```

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-03 --interval 1
```

Terminal 6, run the fixed operator demonstration:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_stage3 --url http://127.0.0.1:8000
Invoke-RestMethod http://127.0.0.1:8000/api/commands | Format-Table command_id,device_id,command_type,status
Invoke-RestMethod http://127.0.0.1:8000/api/sessions | Format-Table device_id,session_id,active
Invoke-RestMethod http://127.0.0.1:8000/api/security-events | Format-Table
```

The helper waits for authenticated telemetry, issues the three specified commands, waits for EXECUTED acknowledgements, republishes the exact protected STOP envelope twice, verifies ALREADY_PROCESSED acknowledgements, revokes device-02, and checks that its commands/telemetry fail while the other devices continue. It uses broker credentials from the same ignored runtime configuration. It prints no keys or credentials. Exact single-execution evidence is asserted against each simulator's processed-ID database in the isolated live test.

To exercise individual endpoints on active devices instead of running the helper:

```powershell
$base='http://127.0.0.1:8000'
Invoke-RestMethod -Method Post "$base/api/devices/device-01/commands" -ContentType 'application/json' -Body '{"command_type":"START","parameters":{}}'
Invoke-RestMethod -Method Post "$base/api/devices/device-02/commands" -ContentType 'application/json' -Body '{"command_type":"CHANGE_THRESHOLD","parameters":{"threshold":35.0}}'
Invoke-RestMethod -Method Post "$base/api/devices/device-03/commands" -ContentType 'application/json' -Body '{"command_type":"STOP","parameters":{}}'
Invoke-RestMethod -Method Post "$base/api/devices/device-01/commands" -ContentType 'application/json' -Body '{"command_type":"UPDATE_CONFIG","parameters":{"telemetry_interval":1.0,"location_enabled":false}}'
Invoke-RestMethod -Method Post "$base/api/devices/device-01/commands" -ContentType 'application/json' -Body '{"command_type":"RESTART","parameters":{}}'
Invoke-RestMethod -Method Post "$base/api/devices/device-03/sessions/rotate"
Invoke-RestMethod -Method Post "$base/api/devices/device-02/revoke"
```

Wait for the RESTART acknowledgement/new session before sending another device-01 command. STOP changes the simulated operational state while keeping heartbeat telemetry and command processing alive.

Stage 3 adds a server `commands` table and uses the existing `sessions.active` column for retained invalidation history; initialization upgrades an existing SQLite registry additively. Existing enrollment `registered`/`revoked` statuses map to API `state: ACTIVE/REVOKED`. Each simulator adds `state.db` with atomic simulated state, processed command IDs, delivery digests and sanitized events. No keys are stored in either database. Command/ACK envelope counters share the existing directional session counters.

Limitations: the local operator API remains unauthenticated; keep it on loopback. ACK loss/reordering or a crash after execution can leave an uncertain/EXPIRED server status; automatic reconciliation/retries are not implemented. Server revocation immediately blocks admission but does not physically disconnect a device or retract an already-issued in-flight command. Local deduplication depends on intact trusted SQLite storage and currently has no retention cap. Lost explicit rotation notifications recover on reconnect/expiry. Simulated effects are transactional; no claim is made about exactly-once physical hardware effects. See [protocol](docs/protocol.md) and [threat model](docs/threat-model.md).
