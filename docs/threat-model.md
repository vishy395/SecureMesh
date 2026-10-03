# SecureMesh threat model through Stage 2

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

Stage 2 authenticates live peers through signed ephemeral handshakes and protects telemetry with AEAD, strict sequence checks and bounded freshness. This custom educational protocol is not independently audited. Commands, command deduplication, attack runner and dashboard remain unimplemented.

Basic revocation is checked during handshake and telemetry admission. CRLs and device-side revocation distribution are not implemented. Stolen valid identity keys permit new-session impersonation until revoked. Availability against dropping/flooding and compromised trusted endpoints is outside the cryptographic guarantees. Clock accuracy is assumed for certificate/session validity and freshness checks.

The API is loopback-only by default and read-only, with no administrator authentication yet. The provisioning CLI is an administrator trust boundary. Restrict local files and do not expose the API externally. Development private keys are unencrypted PEM: POSIX permissions are requested where supported; Windows requires appropriate inherited ACLs. The offline CA must not share its private key with device directories.

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

The API exposes decrypted telemetry to the trusted local operator and remains unauthenticated/read-only on loopback. It must not be exposed publicly. One control-center process owns in-memory sessions; multiple Uvicorn workers/instances are unsupported. Server restart invalidates sessions rather than recovering keys. Device restart/reconnect uses new keys, never persisted counters with reused keys. A server-only restart is recovered immediately by restarting the device, or eventually by session expiry.

The broker can always drop/delay traffic or disconnect clients. Strict replay policy intentionally discards reordered messages, and QoS duplicates may generate rejection events. There is no application telemetry acknowledgement or delivery guarantee. Pending handshakes and receive queues are bounded, but event-log growth and all forms of denial of service are not solved. Identity rotation and the full revocation workflow remain deferred.
