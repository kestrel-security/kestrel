# ADR-0004: Secrets Storage and Encryption

## Status

Accepted. Amended for 0.4.0: ciphertexts are bound to their row with associated data, and master-key rotation is implemented.

## Context

Connector credentials (API tokens, OAuth client secrets) must never be stored in plaintext, logged, sent to an LLM, or returned by the API. Kestrel is meant to be self-hosted by teams without necessarily having a KMS or Vault deployment already, so the v1 mechanism needs to work standalone while leaving a real path to integrate with one later.

## Decision

- `connector_secrets` stores ciphertext only: `id, connector_instance_id, field_name, ciphertext (bytea), nonce (bytea), key_version (int)`.
- **Envelope-style encryption, simplified for v1.** A single root key (`KESTREL_MASTER_KEY`, 32 bytes, base64, from an env var or Docker secret — generated automatically by `kestrel init` if `.env` doesn't already define one) is used to derive a per-org data-encryption key via HKDF (org id as salt), which then encrypts each secret field with AES-256-GCM (via the `cryptography` package's `AESGCM`).
- The derivation is behind a `KeyProvider` protocol (`kestrel/secrets/crypto.py`): `get_data_key(org_id, key_version=None)`, `current_key_version`, and `candidate_key_versions()`. The implementation (`EnvKeyProvider`) derives from `KESTREL_MASTER_KEY` and, during a rotation, `KESTREL_MASTER_KEY_PREVIOUS`; swapping in a real KMS/Vault-backed `KeyProvider` later is additive — call sites depend on the protocol, not the implementation.
- **Every ciphertext is bound to its location (0.4.0).** `encrypt_secret` / `decrypt_secret` take a `context` built by `secret_context(table, row_id, field)` — `kestrel:v1:<table>:<row uuid>:<field>` — and pass it as AES-GCM associated data. A ciphertext copied onto another row, field, or table fails to decrypt. The org is bound separately through the HKDF salt. The same scheme covers every secret-bearing table: `connector_secrets` (the `field_name` is the field), `webhook_endpoints`, `ticket_integrations`, `org_llm_settings`, `operators` (TOTP secret), and `org_smtp_settings`; `kestrel.secrets.rotation.SECRET_LOCATIONS` is the single list.
- **`key_version` is a key id, not a counter (0.4.0).** Each row stores `key_id(master_key)`, 31 bits of an HMAC-SHA256 fingerprint of the key, so an operator who swaps keys cannot mislabel rows; `decrypt_secret` selects the key by the stored id and raises `UnknownKeyVersionError` naming `KESTREL_MASTER_KEY_PREVIOUS` when it is not held. `0` marks rows written before 0.4.0, which carry no associated data and are decrypted without it (trying the current key, then the previous) until `kestrel secrets rotate` re-encrypts them. A bound ciphertext relabelled as `0` does not verify, so the legacy path is not a bypass.
- **Rotation is a re-encryption pass.** Set `KESTREL_MASTER_KEY_PREVIOUS` to the retiring key, `KESTREL_MASTER_KEY` to the new one, restart, run `kestrel secrets rotate`, confirm with `kestrel secrets status`, unset the previous key. Rotation commits per batch under `FOR UPDATE SKIP LOCKED`, so it is safe while the API and worker run. One `secrets.rotated` audit event per organization records the row counts.
- **Redaction is defense-in-depth, not a single point of failure.** Each connector manifest declares its `secret_fields` (e.g. `[token]`); a `SecretRedactor` scrubs those field names recursively from any object before it's logged, sent to an AI provider, or returned via the API — independent of whatever encryption is protecting the value at rest.

## What's explicitly out of scope for v1

External KMS/Vault integration, per-secret DEK envelope layering (today it's root-key → derived-per-org-key → secret, not root-key → per-secret-DEK), and HSM support. Key rotation was out of scope for v1 and is implemented in 0.4.0 as described above; the legacy (version 0) decrypt path exists only for installs that started on a pre-release build (0.4.0 was the first versioned release) and is planned for removal in a later minor, after those installs have run `kestrel secrets rotate`. These are documented here as intentional gaps, not silent ones — self-hosters relying on Kestrel for genuinely sensitive credentials should treat `KESTREL_MASTER_KEY`-based encryption as adequate for reducing at-rest exposure (e.g. a stolen database dump), **not** as a substitute for a production-grade secrets manager. This is called out again in `docs/threat-model.md` and `SECURITY.md`.

## Why this shape

- A real KMS integration point (the `KeyProvider` protocol) exists from day one, even though v1 only ships the simplest implementation of it — this is the difference between "designed for it, simplified for now" and "will need a rewrite later." KMS/Vault, rotation, and HSM remain optional hardening without requiring secret-handling *interfaces* to change.
- Per-org key derivation (rather than one global key encrypting everything) means a compromised derived key for one org doesn't trivially expose another org's secrets, even though all orgs share one root secret in this deployment model.

## Consequences

- Losing `KESTREL_MASTER_KEY` makes every stored secret unrecoverable — operators must back it up (documented in `docs/getting-started.md` and `docs/deployment.md`).
- A row's id is part of its associated data, so code that creates a secret-bearing row must fix the id before encrypting (`row_id = uuid.uuid4()` first, then `encrypt_secret(..., context=secret_context(table, row_id, field))`, then construct the row with `id=row_id`). Relying on the ORM's flush-time default would bind the ciphertext to nothing.
- Adding a new secret-bearing column means adding a `key_version` column beside the ciphertext and nonce, and an entry in `SECRET_LOCATIONS`; a test asserts the list covers every model with a `*_nonce` column.
- `SecretRedactor`'s manifest-driven field list must be kept accurate by connector authors; the connector authoring tutorial calls this out as a required, not optional, part of a manifest.
