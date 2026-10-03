# SecureMesh protocol, version 1

Stage 3 adds secure commands, acknowledgements, durable command deduplication, revocation and session lifecycle to the existing authenticated sessions and encrypted telemetry.

## Identity profile

Device IDs contain 1–64 ASCII letters/digits/underscores/hyphens and start with a letter or digit. IDs are case-sensitive. Every device certificate binds the ID in exactly one subject common name and the URI SAN `urn:securemesh:device:<device-id>`. A caller-supplied ID must agree with both signed fields.

The pinned local CA is self-signed Ed25519, has critical CA basic constraints with path length zero, and certificate-signing key usage. Device certificates have Ed25519 public keys/signatures, unique random serial numbers, issuer equal to the CA subject, critical non-CA basic constraints, critical digital-signature key usage and client-authentication extended key usage. Device validity defaults to 365 days and is bounded by CA validity. Fingerprints are lowercase SHA-256 hex over certificate DER.

Enrollment validates the certificate against the configured public CA trust anchor and stores its fingerprint. Registered identity validation also checks the stored fingerprint and revocation state. Unknown devices cannot authenticate by merely presenting a valid CA-signed certificate. Signed handshake messages prove private-key possession.

The server has a separate Ed25519 certificate: CN `control-center` by default, URI SAN `urn:securemesh:server:control-center`, non-CA constraints, digital-signature key usage and SERVER_AUTH EKU. Device CLIENT_AUTH certificates cannot act as server certificates. Devices trust the configured public CA and pin the exact server certificate fingerprint from their local trusted file. Only the offline provisioning tool reads the CA private key; the running server uses its own identity key.

## MQTT namespace

`securemesh/v1/devices/<device-id>/{handshake,telemetry,commands,acks}`

Implemented handshake subtopics are `handshake/hello`, `handshake/response`, `handshake/finish`, `handshake/ready`; telemetry uses `telemetry`. Topics must match authenticated device IDs. QoS 1 is used; all publishers set retain=false and consumers reject retained messages. Telemetry duplicates are rejected at the security layer; authenticated command redelivery follows the deduplication rules below. The broker is transport, not an identity authority. Commands and acknowledgements use their respective topics.

## Serialization

`canonical_json()` emits UTF-8 JSON with sorted keys, no separator whitespace, unescaped Unicode and rejects NaN/infinity. Inputs must be JSON objects with string keys and JSON-compatible values. This is the SecureMesh Python encoding convention, not full RFC 8785 canonicalization. Handshake fields are strings or exact integers (booleans are rejected as integers); signatures cover re-encoded canonical objects, not arbitrary wire JSON. Base64 is standard padded canonical base64. Parsing rejects duplicate keys, invalid UTF-8, nonfinite numbers, non-object roots and payloads over 65,536 bytes. Schemas reject missing/extra fields. A protocol version other than integer 1 is rejected; no downgrade negotiation exists.

## Four-message handshake

1. **Hello (device → server):** version, type, device ID, intended server identity/fingerprint, device certificate/fingerprint, fresh X25519 public key, fresh 32-byte device challenge, epoch-millisecond timestamp. An Ed25519 signature covers every unsigned hello field with the label `device-hello`.
2. **Response (server → device):** version, type, device ID, server identity/fingerprint/certificate, fresh 128-bit session ID, fresh X25519 public key, fresh 32-byte server challenge, creation/expiration/challenge-expiration times and message limit. The server signs the full transcript with the label `server-response`.
3. **Finish (device → server):** version, type, device ID, session ID, SHA-256 transcript hash and device signature over the same full transcript with the label `device-finish`. The server checks routing/session/hash correspondence and the registered certificate signature before creating an active session.
4. **Ready (server → device):** AES-GCM server-to-device envelope, sequence 1, message type `handshake_ready`. Its encrypted payload binds session ID, transcript hash and status `ready`. Only after authenticating it does the device mark the session authenticated and start telemetry. This provides server key confirmation. Subsequent authenticated telemetry confirms the device's derived key to the server.

Signature input is `b"SecureMesh/v1/" + role_label + b"\x00" + canonical_content`. The full transcript is canonical JSON `{context: "SecureMesh/v1/handshake", hello: unsigned_hello, response: unsigned_response}`. Thus it binds both certificates and fingerprints, identities, challenges, ephemeral keys, protocol version, session ID and lifetimes. Roles have distinct signature labels to prevent reflection.

Device certificates are checked against the CA, registry fingerprint and revocation both on hello and finish. The device checks CA issuance, server role, signed identity and its pinned server fingerprint before accepting the response. An invalid signature never consumes a challenge or activates a session. Accepted signed hello challenges are cached until the hello timestamp's acceptance window closes; replay is rejected. Pending handshakes expire after 15 seconds by default. Cache/pending limits reject new handshakes rather than evict replay evidence early. A restart loses the cache, but the server always generates a fresh response/transcript, so an old finish cannot authenticate a new session.

## Key agreement and derivation

Each attempt generates a fresh X25519 private key on each side. Retries do not reuse keys/challenges. X25519 derives a shared secret; low-order/null shared secrets are rejected by the cryptography library. The raw secret is never used as an AES key.

Let `T = canonical_transcript`, `H = SHA256(T)`. For each direction, HKDF-SHA256 derives 36 bytes with salt `H` and info `b"SecureMesh/v1/session/" + direction + b"/" + H`, using the X25519 shared secret as input. Directions are `device_to_server` and `server_to_device`. The first 32 bytes are that direction's AES-256 key; the final 4 bytes are its nonce prefix. Because T includes identities/session/version, derivation binds these contexts. The two directions have independent labeled outputs.

Ephemeral private-key references are dropped after derivation or pending timeout. Session keys are memory-only and excluded from object representations/logs. Python does not guarantee memory zeroization. SQLite stores only session metadata. Every control-center startup invalidates persisted session rows, and shutdown clears in-memory sessions. One authenticated session is active per device; a successful new handshake supersedes the previous session. Devices restart with a new handshake. Default session lifetime is 600 seconds and each direction is limited to 100,000 messages. Expiration/message limits require a new handshake; long-term identity rotation is not implemented.

## AES-256-GCM envelope

Wire fields: `version`, `message_type`, `device_id`, `session_id`, `sequence`, `direction`, `nonce`, `ciphertext`. The ciphertext includes the 16-byte authentication tag. All six security headers (everything except nonce/ciphertext) are canonicalized as associated data. Nonce/ciphertext are base64. Decryption also checks the nonce equals its deterministic construction, expected direction/type, protocol version and device/session identity. Headers and nonce cannot be changed without rejection.

The 96-bit nonce is **4-byte directional HKDF prefix || 8-byte unsigned big-endian sequence**. Sequences start at 1. A lock reserves/increments the send counter before encryption, so failures burn a number and cannot cause reuse. Counters never wrap/reset within a session key. Fresh handshakes use fresh ephemeral keys and transcript-bound keys. Device telemetry starts at device-to-server sequence 1; server ready uses the separate server-to-device sequence 1. Simultaneous sequence 1 in opposite directions is safe because keys are distinct.

## Telemetry, replay and freshness

Encrypted plaintext fields: `version: 1`, `temperature` (-100..200), `battery` (0..100), `cpu_usage` (0..100), `status` (`running`, `idle`, `warning`), `location: {latitude, longitude}` and `timestamp` (integer epoch milliseconds). Measurements must be finite; latitude is -90..90 and longitude -180..180.

Policy `strict_monotonic` accepts only a sequence greater than the last accepted sequence; gaps are allowed, reordering/duplicates rejected. Zero, negative, boolean, floating, string and over-limit counters are invalid. The server verifies AEAD before labeling a duplicate as an authenticated replay. It checks freshness only on the authenticated plaintext: maximum age 30 seconds, maximum future skew 5 seconds by default. The age limit bounds delayed-message usefulness while skew allows small clock differences. Timestamps supplement sequence numbers; they never replace replay protection.

After authentication, schema validation and freshness, a SQLite transaction conditionally advances the active session's receive sequence, stores telemetry and updates device `last_seen`, including a final revocation check. A control-center lock serializes admission, and SQLite's conditional update provides persistent replay protection. The memory counter advances only after commit. Forged high sequences, bad tags, stale payloads, revoked identities and storage failures never advance replay state.

## Transport and events

MQTT callbacks place messages into a bounded queue; application processing occurs outside the network thread. Clean MQTT sessions, resubscription, SUBACK waiting, reconnect backoff and shutdown are handled by transport. Devices establish fresh cryptographic sessions after broker reconnection. No retained telemetry, offline retransmission or telemetry application acknowledgement is implemented. After a server-only restart, restart the simulator for immediate recovery or wait for its local session expiry.

Sanitized SQLite events record certificate/handshake/signature/session/tag/sequence failures, unknown/revoked devices, replays, stale messages and successful session authentication. Events contain fixed event codes, sanitized device/session IDs and receipt times, never keys, raw payloads or unnecessary readings.


## Stage 3 command envelope and authorization

Commands publish to `securemesh/v1/devices/<device-id>/commands`, with envelope message type `command` and direction `server_to_device`. They reuse the Stage 2 AES-256-GCM envelope, canonical serialization and directional session keys. There is no new cryptographic construction. The pinned control-center handshake identity authenticates the command authority; the MQTT topic and client ID supply routing only.

The encrypted plaintext has exactly:

```json
{"version":1,"command_id":"128-bit lowercase hex ID","target_device_id":"device-01","command_type":"START","parameters":{},"issued_at":0,"expires_at":30000,"session_id":"128-bit lowercase hex ID","sequence":2}
```

Times above illustrate epoch-millisecond fields. Actual issue time is the server clock; expiration is the earlier of issue time plus 30 seconds and session expiration. `command_id` is a random 16-byte value encoded as 32 lowercase hexadecimal characters. Payload `sequence` must be an exact positive integer equal to the authenticated envelope sequence. Commands share the server-to-device counter with ready and session-control messages. A new session resets counters only with fresh keys; it does not reset processed command IDs.

Authentication verifies the live session, version, role/direction, device/session header binding, deterministic nonce and GCM tag. Payload validation then checks target, ID, sequence correspondence, issue time, expiration, supported operation and parameters. The local authorization flag and matching device identity must also permit execution. The server admits commands only for a registered, ACTIVE device with a live authenticated session. A session is the device's authorization lease; the server enforces revocation immediately. There is no broker-trusted authorization or arbitrary shell execution.

The shared command policy is deliberately small:

| Command | Authorized parameters and effect |
| --- | --- |
| START | Empty object; set simulator RUNNING. |
| STOP | Empty object; set simulator STOPPED. Heartbeat telemetry continues to report this state. |
| RESTART | Empty object; increment a simulated restart count, set RUNNING, send ACK, then establish a fresh session. The process remains running. |
| CHANGE_THRESHOLD | Exactly `threshold`: finite integer/float from -100 to 200 inclusive; boolean/string values rejected. |
| UPDATE_CONFIG | Nonempty subset of `telemetry_interval` (finite numeric seconds from 0.1 to 3600) and `location_enabled` (exact boolean). Unknown fields rejected. |

Configuration changes alter telemetry cadence and location reporting. Disabled location produces zero coordinates. Neither configuration field grants filesystem, shell, identity or cryptographic configuration access.

## Command persistence and duplicate delivery

The server `commands` table stores the ID, target, type, structured parameters, issue/expiry times, status, session ID, sequence, acknowledgement and creation/completion times. Statuses are CREATED, SENT, EXECUTED, FAILED, REJECTED and EXPIRED. Creation and session send-sequence metadata commit together with an active-session and registration check. Publication failure burns the cryptographic counter and records FAILED; no nonce is reused. CREATED can survive a crash between persistence and publication; pending CREATED/SENT records expire during maintenance. There is no automatic command retry or offline queue.

On each simulator, `runtime/devices/<device-id>/state.db` stores lifecycle state, threshold, supported configuration, last command and sequence, restart count, processed IDs, authenticated delivery digests and fixed security-event codes. Keys and session counters are not resumed from this database. Simulated state mutation and the processed ID/delivery record commit in a single SQLite transaction, **after** every cryptographic and policy check succeeds. A failed commit produces a protected FAILED acknowledgement and rolls back the simulated effect.

Two replay layers apply:

1. Strict monotonic authenticated envelope sequences reject unknown replays.
2. Durable command IDs prevent a valid command from executing twice, including after a new session or simulator process restart.

For an exact MQTT redelivery, `decrypt_message` still authenticates GCM before its sequence replay error. The handler can then match the exact canonical envelope's SHA-256 digest to a previously validated, committed delivery, revalidate its target/session/expiry/policy and acknowledge ALREADY_PROCESSED. This narrow path never reruns the effect or reduces the receive counter. A fresh valid envelope with an existing ID also acknowledges ALREADY_PROCESSED when its target/type/parameters agree; reusing the ID for a different operation is rejected. Every accepted delivery digest is persisted so a redelivery of this fresh envelope is also harmless. A duplicate after command/session expiry is rejected. Dedup records currently have no automatic retention limit.

## Acknowledgements

ACKs publish to `securemesh/v1/devices/<device-id>/acks`, with envelope message type `ack`, direction `device_to_server`, and a fresh sequence from the counter shared with telemetry. The plaintext has exactly `version`, `command_id`, `device_id`, `status`, `timestamp`, and `command_sequence`. No arbitrary result strings are returned. Status is EXECUTED, ALREADY_PROCESSED, REJECTED or FAILED.

The control center verifies the live ACTIVE device/session and GCM envelope, validates schema and timestamp freshness, then correlates command ID, target, session and original command sequence with persisted metadata. Executed/duplicate ACK timestamps must also lie within the command validity window. It commits the receive sequence and command update together with another active-session/revocation check. Terminal command statuses are preserved on duplicate ACKs; ALREADY_PROCESSED maps a pending command to EXECUTED. A wrong topic, forged ID, bad tag or cross-device ACK cannot update a command. Authentication failures and malformed IDs/targets receive no reflective ACK; authenticated policy/schema/expiration failures with a safe ID and target receive REJECTED.

ACK delivery is not guaranteed: strict ordering can reject a delayed ACK after a newer telemetry sequence, and a lost ACK can leave a successfully executed command SENT until EXPIRED. An operator must not infer that EXPIRED proves no execution. Reconciliation/retries are outside this stage.

## Device and session lifecycle

API registration state is ACTIVE or REVOKED. Existing Stage 1 SQLite enrollment status strings `registered`/`revoked` remain compatible and map to these states; this is distinct from simulator RUNNING/STOPPED and online presence.

`POST /api/devices/{device_id}/revoke` atomically marks the database identity revoked and its session rows inactive, removes its in-memory sessions and pending handshakes, and records device_revocation/session_invalidation events. Hello and finish reject revoked identities; telemetry, commands and ACKs check registry/session state independently. Session history is retained. Offline CLI revocation also marks rows inactive; maintenance drops the corresponding live session objects. Other devices' sessions are unaffected.

`invalidate_session(session_id)` and `invalidate_device_sessions(device_id)` remove live session access, mark session objects unauthenticated, and retain inactive database metadata. Startup and shutdown invalidate sessions because keys are memory-only. Expiration invalidates the old session; reconnect and simulated RESTART initiate a fresh handshake. The device also initiates a handshake when either directional message-count limit is reached.

`POST /api/devices/{device_id}/sessions/rotate` sends an authenticated `session_control` envelope on the command topic. Its exact payload is `{session_id, action: "rotate"}`. The device authenticates it before discarding the old session and reauthenticating. After publication the server invalidates the old session immediately; loss of this notification requires device reconnect or local expiry to recover. Successful replacement invalidates any previous session. Every handshake uses fresh X25519 ephemeral keys and the existing transcript-bound HKDF derivation; Ed25519 identity keys are unchanged. Python cannot guarantee byte-level key zeroization, but invalidated keys are inaccessible to normal message admission.

Telemetry may additionally include `device_state`: state, threshold, configuration, last_command, last_command_sequence and restart_count. Both the original Stage 2 telemetry schema and this validated Stage 3 extension are accepted.

## Stage 3 local operator API

The API validates structured requests and exposes no private/session keys. `POST /api/devices/{device_id}/commands` accepts only `command_type` and `parameters`. `/api/commands` lists public command metadata and validated ACKs. Unknown targets return 404; policy errors 422; revoked/missing-session/publish conflicts 409; disabled MQTT control 503. Revocation remains available in registry-only mode. Mutation endpoints assume a trusted local operator; administrator authentication is not yet implemented. Keep FastAPI bound to loopback and do not expose it to untrusted callers.
