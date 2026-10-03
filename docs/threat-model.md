# Stage 1 threat model

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

Stage 1 cannot demonstrate end-to-end secure traffic. A certificate is public and does not itself authenticate a live sender. Proof of private-key possession, signed handshakes, authenticated encryption, replay defenses, command deduplication and network attack demonstrations arrive in subsequent stages.

Revocation currently affects registry/service validation; there are no active sessions, CRLs or device-side revocation distribution. Stolen valid keys permit impersonation in later communication unless revoked. Availability against dropping/flooding and compromised trusted endpoints is outside the cryptographic guarantees. Clock accuracy is assumed for validity checks.

The API is loopback-only by default and read-only, with no administrator authentication yet. The provisioning CLI is an administrator trust boundary. Restrict local files and do not expose the API externally. Development private keys are unencrypted PEM: POSIX permissions are requested where supported; Windows requires appropriate inherited ACLs. The offline CA must not share its private key with device directories.

Application logging uses a selected metadata allowlist. Persistent audit-event storage and authenticated administrative operations are planned, not completed in Stage 1.
