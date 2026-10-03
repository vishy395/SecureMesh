# SecureMesh

Cryptographic Command & Telemetry Network for IoT Devices, a college cyber defense project. All devices are Python simulators; no physical hardware is required.

**Stage 1 is implemented:** offline CA, Ed25519/X.509 device identities, SQLite registry, certificate validation, basic revocation and a read-only FastAPI API. Encrypted telemetry, authenticated sessions, MQTT communication, commands, dashboard and attack runner are future stages. Their modules are explicit placeholders.

## Architecture

`offline provisioning → CA-signed device certificate → validated SQLite registration`

`FastAPI → service policy → repository → SQLite`

Cryptographic operations live in `securemesh/security/`. The server loads only the public CA certificate. The offline tool alone loads the CA private key. Device private keys live under `runtime/devices/<device-id>/`, never in SQLite.

**CA → Device Certificate → Device Identity:** the trusted CA signs a binding between a device ID and an Ed25519 public key. The registry pins the certificate's SHA-256 fingerprint. A certificate alone does not prove possession of its private key; the authenticated handshake planned for Stage 2 will do that.

MQTT credentials authorize broker access. They do not establish end-to-end device identity: a compromised broker could publish messages or mislabel topics. SecureMesh independently validates cryptographic identities and, in later stages, authenticated messages.

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
.\.venv\Scripts\python.exe -m securemesh.server.main
```

In a second PowerShell terminal, from the repository root:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/devices | Format-Table
.\.venv\Scripts\python.exe -m pytest
```

Stop the server with Ctrl+C. CA initialization and provisioning refuse to overwrite existing identities; on subsequent runs skip initialization and provisioning. `last_seen` remains null because devices do not communicate in Stage 1. `registered` is an enrollment state, not an online state.

Optional offline administrative operations:

```powershell
.\.venv\Scripts\python.exe -m scripts.provision --register-certificate runtime/devices/device-01/device.crt.pem --expected-device-id device-01
.\.venv\Scripts\python.exe -m scripts.provision --revoke-device device-03
```

Certificate-only registration is for a previously unregistered identity; duplicates are rejected. Revocation is persistent and the identity validation service rejects revoked entries. Full session/message enforcement awaits later stages. If provisioning creates files but registration fails, repair registration with `--register-certificate`; do not replace the key automatically.

## Configuration and security limits

Copy `.env.example` to `.env` and change paths/ports as needed. Relative paths are resolved against the working directory. Runtime contents and `.env` are ignored by Git. Mosquitto is not needed for Stage 1; its config is local-only, denies anonymous access and requires a password file before later use.

Keys use exclusive file creation and POSIX mode 0600 where supported; device directories use mode 0700. On Windows, permissions inherit filesystem ACLs: protect `runtime` with account-specific ACLs. Keys are unencrypted development PEM files, so file access controls and a trusted laptop are essential. The CA directory must never be distributed to devices.

The API defaults to loopback and exposes only health and registry metadata; Stage 1 has no administrator login or mutation endpoints. Do not expose it to an untrusted network. Structured application logs contain fixed event names and selected device IDs, never key material. Revocation has no CRL distribution yet. Network confidentiality, proof of private-key possession, replay protection and command security are not implemented.

Certificate validation uses the cryptography library's signature checks plus explicit SecureMesh identity-profile checks; signature verification alone is insufficient. Reference: [cryptography X.509 documentation](https://cryptography.io/en/latest/x509/reference/).
