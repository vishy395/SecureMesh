# Final security validation — Stage 5

Validation date: 3 October 2026 (Asia/Calcutta). This is a local educational protocol review and controlled demonstration, not an independent penetration test or production certification.

## Architecture and protocol review

Offline provisioning creates the Ed25519 development CA and distinct CA-signed device/server identities. The server reads the public trust anchor and its own identity key, never the CA private key. Identity admission validates certificate issuance, validity, Ed25519 algorithm, critical extensions, role/key usage, exact device CN/SAN and registry SHA-256 pin. Device/server keys must match certificates; devices pin the server certificate.

Devices and the control center communicate through authenticated loopback Mosquitto using MQTTTransport. Signed hello/response/finish messages bind role labels, identities, certificate fingerprints, challenges, ephemeral X25519 keys, session parameters and transcript hash. The encrypted ready envelope confirms session keys before device authentication completes. Pending handshakes/challenge caches and transport queues have configured bounds.

Fresh X25519 shared secrets feed HKDF-SHA256 with transcript digest salt and separately labeled directional outputs. Each direction receives a 32-byte AES key and four-byte nonce prefix. AES-256-GCM encrypts canonical JSON with all security headers as associated data. A 12-byte nonce combines the directional prefix with a burned, increasing 64-bit sequence counter. Retries do not reuse counters; restart/reconnect creates new keys. Session expiry/count limits and explicit rotation require fresh handshakes. Session metadata persists but keys remain in memory and cannot resume after server restart. Python does not guarantee memory zeroization.

Secure telemetry follows MQTT topic/identity checks, registry revocation, live session, strict envelope schema, nonce/AAD/tag verification, replay and inner payload/timestamp validation. Only a successful SQLite transaction stores telemetry, last_seen and receive sequence; memory advances after commit. Invalid authentication, stale or invalid payloads do not advance replay state.

Secure commands originate at the trusted loopback operator API, validate exact command/parameter whitelists, select an ACTIVE live session, persist metadata and encrypt with the server-to-device key. The device authenticates before validating target/session/sequence/ID/time/policy. Simulated effects and durable command IDs/delivery digests commit atomically. Exact valid MQTT redelivery returns ALREADY_PROCESSED without another effect. ACKs authenticate in the opposite direction and correlate target, ID, session, sequence and times before transactional server updates. This is simulated transactional execution, not physical exactly-once control.

Revocation atomically marks registration revoked and sessions inactive; the service invalidates live keys and pending handshakes. Every server communication/admission path rechecks registry/session state. New command issuance is rejected. Other devices retain their sessions. Device-side instantaneous revocation distribution and retraction of already-issued in-flight commands are not implemented.

## Audit findings and boundaries

| Area | Review finding |
| --- | --- |
| Identity and authentication | Explicit direct-CA identity profile, distinct server role/pin, Ed25519 proof of possession, role-labeled transcript signatures and key confirmation. No arbitrary public PKI chain support. |
| Exchange/encryption | Fresh X25519; transcript-bound directional HKDF-SHA256; AES-256-GCM; unique per-direction counters and AAD. Existing cryptographic implementation retained. |
| Replay/freshness | Authenticate before replay checks; conditional transactional receive commits; command IDs/digests; handshake cache; timestamps and session lifetime. Reordering intentionally rejected. |
| Authorization | Exact supported command schemas and target binding; revoked server admission fails closed. Local operator API has no login and relies on trusted loopback access. |
| Persistence/input | Parameterized SQL for untrusted values; constrained IDs; duplicate-field/nonfinite JSON rejection; strict request models; bounded wire/queue/handshake sizes. Histories/event and dedup storage remain unbounded over time. |
| Logging | Fixed security codes and selected IDs/sequences; explicit metadata allowlists; no key/session serialization. New CLI errors expose only fixed text, exception class and scenario. |
| Simulator | Real MQTT publications; normal API setup/observation; read-only device dedup evidence; loopback target restrictions; no injection endpoints or production validation changes. Evidence checks remain enabled with Python optimization. |
| Dashboard | Existing persisted security events feed the real Security Events view; no frontend-only results or redesign. Handshake failure remains FAILED and duplicate acknowledgement ACCEPTED under existing presentation; primary rejection codes are BLOCKED. |

No weakening of production validation was required. Live development exposed observer-selection errors when stale/replaced-session traffic was queued; these were fixed in the actor, not in production validation. The existing revocation/in-flight boundary is documented rather than claiming instantaneous endpoint revocation. No newly demonstrated production cryptographic bypass was found within this review's scope.

## Attack coverage

| Attack | Coverage | Observed mechanism |
| --- | --- | --- |
| Ciphertext bit tampering | DEMONSTRATED | invalid_authentication_tag; original row unique; deterministic receive-state invariants. |
| Sequence/AAD tampering with matching public nonce counter | DEMONSTRATED | invalid_authentication_tag. |
| Exact telemetry replay | DEMONSTRATED | replay_attempt; stored once. |
| Exact command replay | DEMONSTRATED | duplicate_command; authenticated duplicate acknowledgement; processed ID once; unchanged execution-event count. |
| Unknown device-999 | DEMONSTRATED | unknown_device; no new session. |
| Known device, independent attacker signing key | DEMONSTRATED | invalid_signature; no new session; victim private key not read. |
| Certificate/claimed ID mismatch | DEMONSTRATED | invalid_certificate; no new session. |
| Device hello ephemeral-key substitution | DEMONSTRATED | invalid_signature and handshake_failure; no new authenticated session. |
| Other transcript/finish modification | DEMONSTRATED in automated regression tests | Signature/hash rejection; no authenticated session and failed-session telemetry rejected. |
| Valid AEAD stale timestamp followed by fresh reading | DEMONSTRATED | stale_message; no receive-state advance; fresh message accepted. |
| Revoked telemetry and authentication | DEMONSTRATED | revoked_device; inactive sessions and fresh signed hello rejected. |
| New command issuance after revocation | DEMONSTRATED | HTTP 409 / revoked_device_command_attempt; no publication. |
| Continued active-device telemetry | DEMONSTRATED | device-01/device-03 counters increase after device-02 revocation. |
| Forward secrecy after later identity-only compromise | THEORETICALLY PROTECTED | Ephemeral X25519, assuming prior ephemeral/shared/session material unavailable; no post-compromise experiment or memory-erasure proof. |
| General MITM / compromised CA or endpoints | NOT COVERED | Only unauthenticated transcript/key substitution and existing peer validation are exercised. |
| Previously issued valid command in transit at revocation | NOT COVERED by instantaneous prevention | No distributed revocation; can execute locally within original lifetime. |
| DoS, external attacks, physical effects, crash reconciliation | NOT COVERED | No availability/security certification or external targeting. |

SecureMesh cryptographically binds the ephemeral X25519 keys to the authenticated handshake transcript, preventing unauthenticated key substitution.

## Automated and live results

Final measured results are recorded after the complete test run below. The isolated live test starts actual Mosquitto, FastAPI and all three simulator subprocesses with temporary identities/free loopback ports, opens the dashboard in a real browser, confirms normal telemetry and three authenticated START acknowledgements, invokes the attack CLI `all`, validates its 12 results, renders each primary event in Security Events, and verifies device-01/device-03 continue while device-02 is revoked. It cleans up only its own subprocesses; existing workspace identities remain untouched. Evidence is retained under ignored `runtime/stage5-review/attack-results.json` and `security-events.png`.

## Assumptions, limitations and future improvements

Trust the laptop, local operator, provisioning, CA configuration, endpoint private-key files, processes and SQLite storage. Windows inherited ACLs must protect unencrypted development PEMs and MQTT credentials. Clock accuracy is required. Plain MQTT exposes credentials/routing/timing; application encryption protects telemetry contents, not availability or metadata. Keep the unauthenticated API on loopback. One control-center process owns sessions; multiple workers are unsupported.

ACK loss/reordering/crash after execution can leave uncertain or expired server status; expiry does not prove nonexecution. Deduplication requires intact trusted device storage. Bounded API histories and concurrent administration can make simulator evidence inconclusive; concurrent attack suites are unsupported. Stale fixtures replace their target session and require disposable identities or a stopped target simulator; `all` confines this to device-02 before revocation. The CLI intentionally fails closed when evidence cannot be obtained.

Future work, not implemented in Stage 5: operator authentication, TLS broker transport, long-term identity rotation, distributed device revocation policy, protected/capped audit and dedup retention, crash/ACK reconciliation, independent protocol review and deployment-specific ACL hardening. No additional features follow this final audit.

## Explicit invariant regression mapping

| Invariant | Verification |
| --- | --- |
| Invalid cryptography never advances replay state | Accepted/unaccepted ciphertext and AAD mutations compare in-memory and persisted receive counters, storage counts and subsequent valid acceptance. |
| Authentication and authorization precede execution | Unauthenticated session, authenticated unauthorized device and tampered command leave restart count and processed IDs unchanged. |
| Duplicate command ID never executes twice | Exact three-delivery regression plus existing fresh-envelope/same-ID and restart cases. Live processed-ID and execution-event counts stay unchanged. |
| Revoked identity cannot establish a session | Dispatch regression and fresh legitimately signed hello after live revocation; session rows inactive. |
| Invalid transcript cannot establish a session | Hello ephemeral/timestamp and finish signature/hash dispatch cases; no authenticated/persisted session; failed-session telemetry rejected. |
| No weakened validation | Production paths exercised directly and over real MQTT; security/transport/device/server validators unchanged; no injection API. |
| Secrets absent from logs/results | Logging/result allowlist checks and public-certificate-only impersonation regression, existing key-persistence/repr/log/dashboard secrecy tests. |
| Evidence required for BLOCKED | No-event timeout and failed-verification cases refuse a result; explicit conditions remain active with Python optimization. |

## Final measured results

- Full `pytest -q`: **230 passed, zero failures, zero skips**, in 80.14 seconds. All 202 existing tests plus 27 new security cases and one new live browser demonstration passed. No security xfails were introduced.
- One existing dependency deprecation warning: Starlette TestClient's httpx integration. No dependency changes were made.
- `python -m pip check`: **No broken requirements found.**
- `git diff --check`: **passed**.
- Standalone live demonstration: **passed**, 12 verified BLOCKED results, three normal commands authenticated/acknowledged, actual dashboard security events visible, active device-01/device-03 continued after revocation.
- The complete test suite also reran this isolated live demonstration successfully. Mosquitto and the installed browser were available; no live/security test was skipped.

## Files changed

- `securemesh/attacks/main.py`: scenario CLI, JSON evidence, fail-closed inconclusive output.
- `securemesh/attacks/scenarios.py`: external loopback MQTT scenarios and observation model.
- `tests/security/test_attacks.py`: 27 additional deterministic security/evidence regression cases.
- `tests/frontend/test_live_attacks.py`: real isolated 12-case CLI/MQTT/browser demonstration.
- `docs/attack-demonstrations.md`: per-case threats, steps, controls, evidence and limits.
- `docs/final-security-validation.md`: final architecture/audit, coverage, validation and limitations.
- `docs/threat-model.md`: final coverage and corrected Stage 4/5 status.
- `README.md`: complete SECURITY DEMONSTRATION commands and final stage status.

`docs/protocol.md` requires no changes: wire protocol and duplicate/revocation semantics are unchanged and already documented. No dependencies or infrastructure were added.


## Persisted live evidence from final suite run

| Attack | Target | Result | Event ID | Event code | Attempt (UTC) |
| --- | --- | --- | --- | --- | --- |
| TELEMETRY_REPLAY | device-01 | BLOCKED | 13 | replay_attempt | 2026-10-03T11:59:10.765414+00:00 |
| COMMAND_REPLAY | device-01 | BLOCKED | 17 | duplicate_command | 2026-10-03T11:59:10.923883+00:00 |
| TAMPER_CIPHERTEXT | device-01 | BLOCKED | 18 | invalid_authentication_tag | 2026-10-03T11:59:12.820269+00:00 |
| TAMPER_HEADER | device-01 | BLOCKED | 19 | invalid_authentication_tag | 2026-10-03T11:59:12.939357+00:00 |
| UNKNOWN_DEVICE | device-999 | BLOCKED | 20 | unknown_device | 2026-10-03T11:59:13.026120+00:00 |
| WRONG_KEY | device-01 | BLOCKED | 22 | invalid_signature | 2026-10-03T11:59:13.110926+00:00 |
| CERTIFICATE_MISMATCH | device-01 | BLOCKED | 24 | invalid_certificate | 2026-10-03T11:59:13.183093+00:00 |
| EPHEMERAL_SUBSTITUTION | device-01 | BLOCKED | 26 | invalid_signature | 2026-10-03T11:59:13.258949+00:00 |
| STALE_MESSAGE | device-02 | BLOCKED | 31 | stale_message | 2026-10-03T11:59:13.362007+00:00 |
| REVOKED_TELEMETRY | device-02 | BLOCKED | 34 | revoked_device | 2026-10-03T11:59:13.571724+00:00 |
| REVOKED_AUTHENTICATION | device-02 | BLOCKED | 35 | revoked_device | 2026-10-03T11:59:13.663766+00:00 |
| REVOKED_COMMAND | device-02 | BLOCKED | 37 | revoked_device_command_attempt | 2026-10-03T11:59:13.749408+00:00 |

Event IDs are scoped to the isolated demonstration database. Full wire digests, sequence/session/command IDs and before/after evidence are retained in `runtime/stage5-review/attack-results.json`; the real browser capture is `runtime/stage5-review/security-events.png`. These ignored artifacts contain no private/session keys or credentials.
