# Stage 3 validation report

Validated on 2026-10-03 using Windows, PowerShell and Python 3.12.2. Stage 3 is complete; dashboard and attack simulator were not implemented. Existing identity signatures, X25519/HKDF derivation and AES-GCM envelope algorithms were reused. The only change to the existing handshake module invalidates the old local session when a fresh handshake starts.

## Changed files

| File | Change |
| --- | --- |
| `securemesh/commands.py` | Exact command schemas, ID/time/target/sequence validation and shared authorization policy. |
| `securemesh/device/commands.py` | Authenticated command processing, atomic simulated effects, durable deduplication, encrypted ACKs and sanitized local events. |
| `securemesh/device/main.py` | MQTT command subscription, ACK publication, lifecycle telemetry, restart and session rotation. |
| `securemesh/protocol.py` | Validated optional lifecycle telemetry extension, preserving Stage 2 telemetry compatibility. |
| `securemesh/security/sessions.py` | Invalidate the prior local session when starting a fresh handshake. |
| `securemesh/server/repository.py` | Command persistence, transactional ACK/sequence commits, final session admission checks and atomic revocation/audit metadata. |
| `securemesh/server/service.py` | Secure command publication, ACK admission, revocation, session invalidation/rotation and maintenance. |
| `securemesh/server/main.py` | Command, revocation and rotation endpoints; command listing; ACK subscription; Stage 3 health metadata. |
| `scripts/demo_stage3.py` | Fixed local operator demonstration using running services and three disposable device registrations. |
| `tests/security/test_commands.py` | 66 command/security/deduplication/session/storage/isolation tests. |
| `tests/integration/test_commands_api.py` | 12 API schema/policy/availability/revocation tests. |
| `tests/integration/test_mqtt_commands.py` | Three real-broker tests: three-device demonstration, automatic expiry rotation and automatic message-limit rotation. |
| `docs/protocol.md` | Commands, authorization, ACKs, IDs, sequences, deduplication, invalidation and rotation. |
| `docs/threat-model.md` | Stage 3 threats, controls and remaining trust boundaries. |
| `README.md` | Updated feature status and exact automated/manual demonstration commands. |
| `docs/stage3-validation.md` | This review and validation record. |

No dependency, dashboard, attack-simulator or deployment changes were made.

## Database changes

Initialization additively creates the server `commands` table with command_id, device_id, command_type, parameters, issued_at, expires_at, status, session_id, sequence, acknowledgement, created_at and completed_at. Existing Stage 1/2 tables and enrollment status values remain compatible. The existing `sessions.active` field retains invalidation history; revoked sessions are never deleted. API state maps enrollment to ACTIVE/REVOKED.

Each simulator uses a local SQLite `state.db` containing state, processed command IDs, authenticated delivery digests and sanitized events. This uses the existing SQLite technology, not a new database service. State mutation and dedup records commit atomically. No private keys, session keys, ephemeral private keys or shared secrets are persisted. Runtime artifacts remain ignored by Git; the live tests use isolated temporary databases and identities.

## Security review

| Review item | Result |
| --- | --- |
| MQTT topic as authority | Topic supplies routing only; authenticated session, direction and device bindings are required. |
| Execution or processed-ID insertion before authentication | Neither occurs until GCM, payload freshness/expiry, target, ID, sequence and policy validation succeeds. |
| Repeated command execution | Durable command IDs and delivery digests; two/three/many deliveries and restored handlers tested. |
| Revoked identities retaining usable sessions | API revocation invalidates memory/pending handshakes and database rows. Offline revocation invalidates rows atomically; maintenance drops memory. Every admission path checks state. |
| Revocation during session/command commit | Final SQLite registration/session checks prevent stale admission races. |
| Old session messages | Replacement/expiry/invalidation makes old sessions unusable; fresh handshakes derive different directional keys. |
| Cross-device commands/ACKs | Header, payload, local device identity and persisted-command correlation reject injection. Three-device tests verify isolation. |
| Arbitrary configuration injection | Only telemetry_interval and location_enabled accepted, with exact types/ranges. |
| Secret persistence/API/logging | Explicit metadata allowlists; tests inspect persisted/public data for key bytes and encoded key values. Events use fixed codes. |
| ACK forgery/tampering | No command status update before authenticated validation and transactional replay-state commit. |
| Final counter consumed by an ACK | Simulator checks rotation both before receiving messages and after command processing, before telemetry encryption. |

## Test and dependency results

Final commands executed:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Results: **181 passed, zero failed, zero skipped**, in 27.96 seconds. This includes all 100 original Stage 1/2 tests and 81 new Stage 3 tests. One existing FastAPI/Starlette TestClient deprecation warning concerns its httpx integration. `pip check`: **No broken requirements found.** `git diff --check`: clean.

All four live MQTT tests ran successfully: the original Stage 2 telemetry/replay test and three Stage 3 tests. Mosquitto was discovered at `runtime/tools/mosquitto/mosquitto.exe`; no broker download or system service was required.

## Live demonstration results

The three-device test started real Mosquitto, FastAPI, device-01, device-02 and device-03 subprocesses on isolated loopback ports. All authenticated and sent encrypted telemetry. START, CHANGE_THRESHOLD and STOP reached only their intended devices and generated authenticated EXECUTED ACKs. Two exact redeliveries generated ALREADY_PROCESSED ACKs while the device database retained one execution record for the command. Unit tests additionally prove RESTART increments once under repeated delivery.

A simulated RESTART kept device-01 running and established a new session. Explicit rotation established a new device-03 session. The standalone `scripts.demo_stage3` helper was also launched and passed against these real processes. Revocation marked device-02 REVOKED and all its session history inactive; telemetry and commands were rejected. device-01/device-03 continued sending accepted telemetry. Separate real-broker tests each stored 20 readings across multiple fresh sessions when a one-second session lifetime or four-message limit triggered automatic rotation.

Every test-launched process was stopped during cleanup. Existing workspace device registrations were not revoked by these demonstrations.

## Reproduce

Run the isolated demonstration and full validation from the repository root:

```powershell
$env:SECUREMESH_MOSQUITTO_EXE=(Resolve-Path .\runtime\tools\mosquitto\mosquitto.exe).Path
.\.venv\Scripts\python.exe -m pytest tests/integration/test_mqtt_commands.py -v -s
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

For manual execution, use the exact per-terminal broker, server, three-device and helper commands in [README](../README.md#stage-3-demonstration-powershell). The helper issues supported commands, duplicates a protected envelope and **permanently revokes device-02**; use disposable registrations. It never prints credentials or keys.

## Known limitations

- The local operator HTTP API is unauthenticated and assumes trusted loopback callers.
- Lost/reordered ACKs or a crash after execution can leave an uncertain/EXPIRED server status. No automatic retry/reconciliation is implemented; EXPIRED does not prove absence of execution.
- Revocation immediately stops server admission. A device may keep publishing rejected messages until expiry/reconnect, and a command issued before revocation may still execute within its original validity window.
- Deduplication depends on intact trusted local storage; history has no retention cap. Transactional simulated effects do not imply exactly-once physical hardware side effects.
- A lost explicit rotation notification recovers on reconnect or expiry. Session keys remain memory-only, but Python does not guarantee zeroization.
- One control-center process owns live sessions; multiple workers and distributed operation remain unsupported. Long-term identity rotation, CRL distribution, protected audit retention and denial-of-service resilience remain outside Stage 3.
