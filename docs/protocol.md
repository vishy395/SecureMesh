# SecureMesh protocol, version 1

Stage 1 defines identity and wire conventions only. No telemetry, handshake, command or encrypted envelope is currently transmitted.

## Identity profile

Device IDs contain 1–64 ASCII letters/digits/underscores/hyphens and start with a letter or digit. IDs are case-sensitive. Every device certificate binds the ID in exactly one subject common name and the URI SAN `urn:securemesh:device:<device-id>`. A caller-supplied ID must agree with both signed fields.

The pinned local CA is self-signed Ed25519, has critical CA basic constraints with path length zero, and certificate-signing key usage. Device certificates have Ed25519 public keys/signatures, unique random serial numbers, issuer equal to the CA subject, critical non-CA basic constraints, critical digital-signature key usage and client-authentication extended key usage. Device validity defaults to 365 days and is bounded by CA validity. Fingerprints are lowercase SHA-256 hex over certificate DER.

Enrollment validates the certificate against the configured public CA trust anchor and stores its fingerprint. Registered identity validation also checks the stored fingerprint and basic revocation state. Unknown devices cannot authenticate by merely presenting a valid CA-signed certificate. Certificate possession is not yet proof of private-key possession.

## Planned MQTT namespace

`securemesh/v1/devices/<device-id>/{handshake,telemetry,commands,acks}`

Topic IDs will be checked against authenticated identities. The broker is a transport, not an identity authority. Later stages will define handshake subtopics, schemas, signed transcripts, authenticated headers, sequence rules and command acknowledgements before sending messages.

## Serialization

`canonical_json()` emits UTF-8 JSON with sorted keys, no separator whitespace, unescaped Unicode and rejects NaN/infinity. Inputs must be JSON objects with string keys and JSON-compatible values. This is the SecureMesh Python encoding convention, not full RFC 8785 canonicalization. Later signed schemas must restrict numeric representations and define parsing/duplicate-key rejection; changing the wire encoding requires a protocol version decision.
