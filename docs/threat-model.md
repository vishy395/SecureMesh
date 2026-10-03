# SecureMesh threat model through Stage 5

## Trusted components

- Local laptop, control-center process and SQLite database.
- Administrator-controlled offline provisioning process.
- Configured CA certificate as the trust anchor; the CA private key remains offline from the API.
- Protected device private-key files and administrator filesystem permissions.

The network is potentially hostile. A broker may observe, inject, modify, relabel or drop messages and is not trusted to establish identity.

## Implemented controls

Ed25519 X.509 certificates bind device IDs to public keys. Validation checks CA self-signature/profile, device issuance signature, validity, CN/SAN identity, device certificate usage and registered SHA-256 fingerprint. The registry rejects duplicate identity replacement, unknown identities and revoked identities through the service. SQL is parameterized. IDs are constrained to prevent path/topic injection. Private keys are generated offline and never stored in SQLite or returned by the API. Key writes refuse overwrites.

CA trust derives from trusted configuration, not merely from the CA being self-signed. The certificate validator implements this project's direct-CA identity profile, not arbitrary public PKI path building.

## Remaining limitations

SecureMesh authenticates live peers through signed ephemeral handshakes and protects telemetry with AEAD, strict sequence checks and bounded freshness. This custom educational protocol is not independently audited. Stage 3 implements commands, durable deduplication, acknowledgements and session/device lifecycle. Stages 4 and 5 add the operational dashboard and controlled local attack runner.

Revocation invalidates active sessions and is checked during handshake, telemetry, commands and acknowledgement admission. CRLs and device-side revocation distribution are not implemented. Stolen valid identity keys permit new-session impersonation until revoked. Availability against dropping/flooding and compromised trusted endpoints is outside the cryptographic guarantees. Clock accuracy is assumed for certificate/session validity and freshness checks.

The API is loopback-only by default with validated command, revocation and rotation mutations, with no administrator authentication yet. The provisioning CLI is an administrator trust boundary. Restrict local files and do not expose the API externally. Development private keys are unencrypted PEM: POSIX permissions are requested where supported; Windows requires appropriate inherited ACLs. The offline CA must not share its private key with device directories.

Application logging uses a selected metadata allowlist. Sanitized security events persist in SQLite. Administrative authentication, protected audit storage and audit retention/rate limits remain future work.

## Threats addressed by Stage 2

| Threat | Control and boundary |
| --- | --- |
| Passive network/broker observer | AES-256-GCM hides telemetry values. Public certificates, device IDs, topics, timing and message sizes remain visible. Plain MQTT credentials are also visible on the transport; they are not identity credentials. |
| Message tampering | AEAD authenticates ciphertext, nonce and security-sensitive headers. Invalid tags/headers cannot update replay state or last_seen. |
| MITM ephemeral-key substitution | Signed canonical transcripts bind both ephemeral keys, challenges, identities, fingerprints, version and session lifetime. |
| Replay | Signed hello challenge cache; single-use finish state; authenticated strictly increasing telemetry counters and conditional SQLite commit. |
| Stale/delayed messages | Handshake challenge expiry and authenticated telemetry timestamp age/future-skew limits. Sequences remain the main replay defense. |
| Forged device | CA/profile/identity checks, registry fingerprint pin and Ed25519 proof of possession. A broker topic or valid but unregistered certificate is insufficient. |
| Forged server | Distinct server-authentication certificate role, CA validation, exact locally pinned server fingerprint, transcript signature and encrypted ready/key confirmation. |
| Session hijacking | Transcript-bound X25519/HKDF keys, independent directional keys, session/topic identity checks and authenticated metadata prevent traffic injection without session keys. |
| Later identity-key compromise | Fresh ephemeral keys provide forward secrecy for earlier completed sessions assuming ephemeral/session material was not captured. Python cannot guarantee secret-memory erasure. |

## Operational limitations

Local filesystem/SQLite/control-center/device processes remain trusted. Development keys and broker client credentials are unencrypted files; Windows ACLs must protect them. The server loads its own identity key but never the CA private key. Do not distribute the server private key or CA directory to devices; only public trust anchors are needed there.

The API exposes decrypted telemetry to the trusted local operator and remains unauthenticated on loopback for a trusted local operator. It must not be exposed publicly. One control-center process owns in-memory sessions; multiple Uvicorn workers/instances are unsupported. Server restart invalidates sessions rather than recovering keys. Device restart/reconnect uses new keys, never persisted counters with reused keys. A server-only restart is recovered immediately by restarting the device, or eventually by session expiry.

The broker can always drop/delay traffic or disconnect clients. Strict replay policy intentionally discards reordered messages, and QoS duplicates may generate rejection events. There is no application telemetry acknowledgement or delivery guarantee. Pending handshakes and receive queues are bounded, but event-log growth and all forms of denial of service are not solved. Long-term identity rotation remains deferred; Stage 3 implements server-side device revocation.


## Threats addressed by Stage 3

| Threat | Control and boundary |
| --- | --- |
| Forged commands | Only envelopes authenticated by a live server-to-device key from the pinned control-center handshake can reach command policy or execution. Topics, client IDs and plaintext routing IDs grant no authority. |
| Command tampering | Existing AES-GCM authenticates ciphertext and every security header; target/session/command sequence are also validated inside the plaintext. No execution or processed-ID insertion occurs before authentication and validation. |
| Command replay | Strict authenticated sequence validation plus durable command-ID deduplication. Unknown replay sequences fail closed. |
| MQTT redelivery | Exact authenticated delivery digests identify already committed commands; return a fresh encrypted ALREADY_PROCESSED ACK without a second effect. Same IDs in fresh valid envelopes also deduplicate. |
| Cross-device injection | Session header, inner target, locally configured device identity, role/direction and server ACK correlation all bind the intended device. Three-device tests exercise isolation. |
| Arbitrary configuration injection | Exact shared command schemas and a two-field config whitelist. No shell, filesystem paths, identity replacement or arbitrary configuration keys. |
| Forged ACK | Live-session authentication, target/session/command-ID/sequence correlation and timestamp validation before transactional status update. |
| Revoked-device communication | Atomic registry revocation/session-row invalidation; in-memory session/pending-handshake invalidation; independent admission checks for every path. Other devices retain their sessions. |
| Stale sessions | Expiry, count-driven reauthentication, explicit protected rotation, restart/reconnect and successful session replacement. Fresh X25519 keys and HKDF outputs; old session messages cannot resume from metadata. |
| Secret persistence or logging | Explicit metadata allowlists; databases store no session/private keys. Events contain fixed codes and validated IDs, never raw command payloads or cryptographic secrets. |

## Stage 3 boundaries and limitations

Authorization is a deliberately small policy for a trusted local operator, independent of cryptographic peer authentication. The HTTP API has no administrator authentication yet; an untrusted local caller able to reach it can request supported commands or revocation. Input validation does not authenticate an operator. Do not expose mutation endpoints to an untrusted network. The MQTT broker cannot independently forge supported commands even if it labels traffic as a control-center publication.

Revocation is authoritative at the server. No distributed CRL or instantaneous device notification is implemented: a simulator may continue publishing rejected envelopes until reauthentication/expiry, and a previously issued valid command already in transit may execute locally within its original session/command lifetime. Server acceptance stops immediately at revocation. Broker disconnection is not required for cryptographic revocation.

Deduplication protects simulated effects because effects and IDs share one local SQLite transaction. It does not claim exactly-once execution of future physical hardware or external side effects. Trusted storage must remain intact; deleting or restoring older simulator state can erase deduplication evidence. Process crashes after commit but before ACK leave a completed local effect and an uncertain server status. Fresh valid redelivery can acknowledge it; automatic retry/reconciliation is not implemented. Loss, ordering and ACK delays can produce EXPIRED even after execution.

Explicit rotation notification can be dropped by a hostile broker. Old keys remain rejected at the server, while recovery waits for reconnect or local expiry. Python cannot prove secret-memory erasure. Unbounded dedup/event history, audit tampering by trusted filesystem users and denial of service remain operational limitations. Identity-key rotation and additional database services remain outside scope.


## Final attack coverage (Stage 5)

Real loopback MQTT demonstrations cover ciphertext/AAD tampering, telemetry replay, command redelivery without repeated effects, three device impersonation variants, signed-hello ephemeral substitution, authenticated stale telemetry with fresh recovery, and revoked-device telemetry/authentication/command issuance. The dashboard displays persisted backend events. See [attack demonstrations](attack-demonstrations.md) for preconditions, evidence and exact boundaries and [final validation](final-security-validation.md) for measured results.

The external actor has broker credentials; these grant transport publication, not identity. Public victim certificates plus an independent attacker key cannot authenticate. Only controlled stale/MITM fixtures use authorized device identity material to construct a valid baseline, through the normal protocol. No endpoint bypass or relaxed production validator is introduced. Revocation does not retract valid commands already in transit. Availability, compromised endpoints/CA, immediate distributed revocation and physical exactly-once effects are NOT COVERED. Forward secrecy against later identity-only compromise is THEORETICALLY PROTECTED by ephemeral X25519, subject to trusted endpoints and uncaptured ephemeral/session material; the attack suite does not empirically demonstrate memory erasure or post-compromise recovery.
