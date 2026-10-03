# SecureMesh

Cryptographic Command & Telemetry Network for IoT Devices, a college cyber defense project. All devices are Python simulators; no physical hardware is required.

**Stages 1-5 are implemented:** offline CA, Ed25519/X.509 identities, SQLite registry, mutual authentication, ephemeral X25519 sessions, directional HKDF keys, AES-256-GCM telemetry and commands, authenticated acknowledgements, durable command deduplication, device lifecycle, revocation, session rotation and a local control-center dashboard. Stage 5 adds a local MQTT attack simulator and final security validation; long-term identity rotation remains future work.

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


## Stage 4 control-center dashboard

The dashboard is served by FastAPI at **http://127.0.0.1:8000/**. There is no separate frontend server, Node installation or build step. Native JavaScript modules and project-specific CSS provide overview, registry, device detail, telemetry, command center and security-event views. The cryptographic protocol and existing mutation endpoints are unchanged.

Start the broker, FastAPI and three devices in separate terminals, using the provisioned ACTIVE identities from the installation section:

```powershell
& .\runtime\tools\mosquitto\mosquitto.exe -c .\runtime\mqtt\mosquitto.conf
```

```powershell
$env:SECUREMESH_MQTT_ENABLED='true'
.\.venv\Scripts\python.exe -m securemesh.server.main
```

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-01 --interval 1
```

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-02 --interval 1
```

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-03 --interval 1
```

Open http://127.0.0.1:8000/ in your browser. Inspect all three registry entries, navigate to Command center and issue START, CHANGE_THRESHOLD and STOP to their respective devices. Review each confirmation, then observe EXECUTED and the authenticated acknowledgement. Device detail exposes certificate metadata, session history and current accepted simulator state; it also offers session rotation and confirmed revocation. Revocation is permanent for that registration: use disposable identities for demonstration.

One read-only `GET /api/dashboard` endpoint provides exact database totals, public registry metadata, certificate validity dates, live-session state, latest readings and bounded histories. Optional `device_id` scopes histories to one device. The default history limit is 200 (maximum 500); view filters apply to the labeled recent window. Unknown backend event types remain INFO, and administrative revocation/invalidation is distinct from blocked communication.

A single request refreshes the snapshot every five seconds; hidden tabs pause, errors back off to 30 seconds, and mutation completion refreshes immediately. Failed requests preserve visible data with a stale-data notice. Command drafts and keyboard focus survive refreshes. The visual system and actual API map are documented in [docs/DESIGN.md](docs/DESIGN.md).

**Local trust boundary:** no administrator login is implemented. Keep FastAPI bound to loopback and restrict local operator access. The dashboard exposes accepted telemetry and public metadata, never private keys, CA private keys, session keys, shared secrets or broker credentials. Browser controls supplement backend authorization; they do not replace it.

### Dashboard validation

Install the existing test extras. Browser tests use installed Microsoft Edge/Chrome on Windows or `SECUREMESH_BROWSER_EXE`; if neither exists, install Playwright Chromium:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
# Only when an installed supported browser is unavailable:
.\.venv\Scripts\python.exe -m playwright install chromium
```

Run real-browser and backend checks:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/frontend tests/integration/test_dashboard_api.py -v
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

The live dashboard test launches isolated Mosquitto, FastAPI and three actual simulators; it uses the rendered UI to issue all five commands, waits for authenticated ACKs, verifies restart and revocation, and checks security-event rendering. It creates disposable registrations and does not revoke your existing workspace devices. It captures desktop/mobile review images under ignored `runtime/stage4-review/`. The test requires Mosquitto and a supported browser and must pass without skipping for full Stage 4 validation. No frontend lint/type-check configuration exists; native module parsing, data mapping and interaction behavior are exercised in the real browser.

## SECURITY DEMONSTRATION (Stage 5)

Use disposable ACTIVE registrations. The complete suite permanently revokes device-02 and uses its identity for a controlled stale-message fixture. It leaves device-01/device-03 running. Installation, provisioning and one-time broker setup commands are above.

Start Mosquitto in terminal 1:

```powershell
& .\runtime\tools\mosquitto\mosquitto.exe -c .\runtime\mqtt\mosquitto.conf
```

Start FastAPI in terminal 2:

```powershell
$env:SECUREMESH_MQTT_ENABLED='true'
.\.venv\Scripts\python.exe -m securemesh.server.main
```

Start one device in each of terminals 3, 4 and 5:

```powershell
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-01 --interval 1
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-02 --interval 1
.\.venv\Scripts\python.exe -m securemesh.device.main --device-id device-03 --interval 1
```

Open the dashboard and issue a normal command in terminal 6:

```powershell
Start-Process 'http://127.0.0.1:8000/'
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/devices/device-01/commands -ContentType 'application/json' -Body '{"command_type":"START","parameters":{}}'
Invoke-RestMethod http://127.0.0.1:8000/api/commands
```

Wait for EXECUTED and its authenticated acknowledgement. Run the full suite on a fresh disposable setup, or the individual commands below. Do not run `all` after an individual revocation:

```powershell
.\.venv\Scripts\python.exe -m securemesh.attacks.main --list
.\.venv\Scripts\python.exe -m securemesh.attacks.main all
```

Individual scenarios:

```powershell
.\.venv\Scripts\python.exe -m securemesh.attacks.main replay --device-id device-01
.\.venv\Scripts\python.exe -m securemesh.attacks.main tamper --device-id device-01
.\.venv\Scripts\python.exe -m securemesh.attacks.main impersonate --device-id device-01
.\.venv\Scripts\python.exe -m securemesh.attacks.main mitm --device-id device-01
# Stop device-02's simulator before this controlled session; restart it afterward.
.\.venv\Scripts\python.exe -m securemesh.attacks.main stale --device-id device-02
# With ACTIVE device-02 publishing again, this permanently revokes it:
.\.venv\Scripts\python.exe -m securemesh.attacks.main revoked --device-id device-02
```

All traffic targets loopback only. Optional `--url http://127.0.0.1:<port>` selects the local API; MQTT/runtime settings use existing environment configuration. JSON results require persisted backend evidence. A failed capture/verification prints INCONCLUSIVE and exits 1. Security Events shows the actual persisted rejections; exact command redelivery is safely acknowledged as ALREADY_PROCESSED and displays the existing DUPLICATE_COMMAND / ACCEPTED event, while the repeated effect is BLOCKED.

Repeatable isolated live demonstration, including real broker, FastAPI, three simulator processes, normal authenticated commands, all 12 attack cases, browser Security Events and continuity after revocation:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/frontend/test_live_attacks.py -v -s
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

The live test requires Mosquitto and a supported installed browser, as described above. Evidence and screenshot are saved under ignored `runtime/stage5-review/`. It uses temporary identities and never revokes workspace registrations. See [attack demonstrations](docs/attack-demonstrations.md) and [final validation](docs/final-security-validation.md) for precise scope and limitations.
