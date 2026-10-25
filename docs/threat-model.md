# Threat Model

Kestrel is security-sensitive by nature: it aggregates identity, access, and credential metadata across every connected SaaS application for an organization. This document describes what Kestrel protects against today, what it explicitly does not yet protect against, and why — consistent with the project's principle of documenting scope gaps rather than leaving them implicit.

**Also see:** root [`SECURITY.md`](../SECURITY.md) and [`architecture.md`](architecture.md).

## Assets

- **Connector credentials** (API tokens, OAuth client secrets) — the highest-value asset. Compromise gives an attacker read (and sometimes write) access to every connected SaaS application.
- **Normalized identity/access/finding data** — reveals an organization's privileged users, MFA gaps, external access, and security posture. Valuable reconnaissance for an attacker even without connector credentials.
- **The KESTREL_MASTER_KEY** — root key for connector-secret encryption (ADR-0004). Compromise decrypts every stored connector secret.
- **The Kestrel database** — a single compromise point for all of the above in a typical single-org deployment (single Postgres instance).

## Trust boundaries

```
Untrusted: external SaaS APIs (connector targets), AI providers (if configured)
    │
    ▼
Kestrel connectors (collector/normalizer) ── no DB access by API design, only Transport (not sandboxed; see below)
    │
    ▼
Kestrel core (kestrel/) ── has full DB access, decrypts secrets when authenticating a live connector
    │
    ▼
Kestrel API / worker / CLI ── the only components with DB credentials
    │
    ▼
Kestrel web UI ── talks only to the API, never directly to the DB
    │
    ▼
End user's browser ── untrusted input surface (findings/policy text rendered, form submissions)
```

## What Kestrel protects against today

- **Authentication and RBAC on the API and UI** (ADR-0008): every API route requires a valid bearer token (`Authorization: Bearer <opaque token>`, checked against `OperatorSession` or `ApiToken` rows via `get_current_operator`); mutating routes additionally require a minimum role (`read_only` < `analyst` < `admin`) via `require_role`. Passwords are hashed with Argon2id; login lockout (5 failed attempts, 15-minute lock, incremented with one atomic `UPDATE ... RETURNING` so parallel guesses cannot race past it) and uniform failure responses (including equal Argon2 work on unknown, inactive and locked accounts) prevent brute-forcing and user enumeration. A password change revokes the operator's other sessions; an admin reset revokes all of them and, by default, the operator's API tokens. Every operator/finding/connector mutation and every login/logout is recorded in `audit_log` with a real `actor_operator_id`, not a free-text string.
- **Multi-factor authentication** (DEC-028): operators can enrol a TOTP authenticator, and admins can require it for every operator. An enrolled operator's password only opens a five-minute challenge that reaches nothing but the code check; wrong codes count toward the same lockout as wrong passwords, codes cannot be replayed, and the secret is encrypted with the org key. API tokens are exempt by design (automation) but an operator with MFA can only mint one from a session that passed it, so a stolen password alone cannot.
- **Mail server settings** (DEC-029): the SMTP password an admin saves at Settings → Email is encrypted with the org key, never returned, and must be re-entered when the host, port or username changes, so it cannot be redirected to another server. The host may be private or loopback (internal relays are normal) but never link-local or a cloud-metadata address, checked on save and again before each connection.
- **Secrets at rest**: connector credentials, webhook signing secrets, ticketing tokens, LLM API keys, TOTP secrets, and SMTP passwords are stored as AES-256-GCM ciphertext, never plaintext, via envelope encryption keyed off `KESTREL_MASTER_KEY` (ADR-0004, `kestrel/secrets/crypto.py`). GCM's authentication tag makes tampering with stored ciphertext detectable, not just silently wrong, and every ciphertext is bound to its table, row, and field through associated data, so someone with write access to the database cannot swap one row's secret for another's (say, point a connector at a lower-value token, or move an admin's TOTP secret onto their own account) without it failing to decrypt. Each row records the id of the master key that wrote it, and `kestrel secrets rotate` re-encrypts everything under a new key.
- **Policy code runs away from the secrets**: operator- and AI-written policies compile with RestrictedPython and evaluate in a child process with wall-clock, CPU, and memory limits. That child starts with an allowlisted environment (`PATH`, locale, interpreter variables); `KESTREL_MASTER_KEY`, `DATABASE_URL`, `REDIS_URL`, and every other `KESTREL_*` setting stay in the parent, so an escape from RestrictedPython does not by itself yield the key that decrypts every stored secret or a database connection string.
- **Secrets in logs/AI payloads/API responses**: `kestrel.secrets.store.redact` recursively scrubs any connector manifest's declared `secret_fields` from arbitrary nested structures — a second layer of defense independent of encryption at rest. Structured JSON request logging (`kestrel_api/middleware/logging.py`) never logs request/response bodies, only method/path/status/duration, so credentials passed in a request body can't leak via access logs by construction.
- **SSRF on connector configuration**: `kestrel.security.ssrf` resolves the hostname of any `http(s)://` URL in connector-instance config and rejects every non-global address (private, loopback, link-local/cloud metadata, CGNAT `100.64.0.0/10`, documentation, benchmarking) plus reserved and multicast ones, applied at `POST`/`PATCH /connector-instances` and immediately before `LiveHTTPTransport` opens a real HTTP client. Best-effort: the resolved address is not pinned for the connection, so DNS rebinding between validation and connect is an accepted residual risk.
- **Credential exfiltration by re-pointing an integration**: whoever may edit a connector's config (analyst) could otherwise change its `org_url` / `base_url` to their own server and collect the stored token on the next test or sync. Changing any URL / host config field clears the stored secrets unless new ones are supplied in the same request (audited as `secrets_cleared`), live-mode credential URLs must be `https`, and Okta org URLs must be on Okta-owned domains. The Jira `base_url` and the org LLM endpoint require the token / key to be re-entered with the change.
- **CSV formula injection**: every CSV export neutralises cells that a spreadsheet would evaluate as a formula (leading `= + - @`, tab, CR), since exports carry SaaS-controlled names.
- **Tenant isolation**: every query is scoped by `org_id` at the application layer (ADR-0006); every entity table carries it from the first migration.
- **SQL injection**: all queries go through SQLAlchemy's parameterized query builder or bound parameters in raw SQL (`kestrel/graph/queries.py`'s recursive CTE uses named bind parameters, never string interpolation of user input).
- **Idempotent, auditable sync**: entity upserts are keyed by `(application_instance_id, provider_object_id)`; `events` rows record what changed, when, and from which connector run — an attacker (or a bug) silently altering collected data leaves a trail. Only one sync per connector instance runs at a time (a Redis lock plus a `connector_runs` guard), so two interleaving runs cannot compute deletions against each other's half-written inventory.
- **Secrets in error text**: provider errors repeat request URLs and occasionally headers, so `kestrel.secrets.scrub.scrub_text` removes known secret values, credential-shaped strings (GitHub, Slack, Google, JWT), and every URL query string before an error reaches `ConnectorRun.error_summary` or an API response. The pre-save connection probe (`POST /connectors/probe`) accepts secrets in the request body, holds them in memory for the duration of one health check, persists nothing, and scrubs its own result — its audit event records the outcome, never the inputs.
- **Access decisions reflect current state**: a row the provider stops reporting is tombstoned and disappears from policy evaluation, the identities API, search, and the graph, so a revoked account cannot keep matching a policy — or keep an operator believing access exists after it is gone.

## What Kestrel does not yet protect against (explicit gaps)

These are documented scope boundaries, not oversights:

- **No SSO/SCIM yet.** Auth is local email/password only; ADR-0008 documents the extension points these will attach to (an additive `/auth/sso/callback`, a `/scim/v2/Users` writer to the same `operators` table) without a schema redesign.
- **No email-based invite or password-reset flow.** Operators are created with a password set directly (by an admin via the API/CLI/UI, or auto-generated by `kestrel init`) — there's no "send an invite link" or "forgot password" email flow yet. Until then, an admin resets a locked-out or forgotten password from Settings → Operators (or `kestrel operator set-password`), which also ends that operator's sessions.
- **CSRF has a narrow, by-construction defense, not a general-purpose one.** FastAPI never accepts cookie-based auth — only a bearer token in the `Authorization` header, which a cross-site request can't forge the way it auto-attaches cookies — so classic CSRF doesn't apply to the API itself. The actual session cookie lives only in the Next.js app (`httponly`/`samesite=lax`, and `secure` whenever `APP_URL` is `https`, plus Next's own Server Action origin checks); `OriginCheckMiddleware` on the API is an opt-in (`ALLOWED_ORIGIN`) defense-in-depth backstop, not the primary control. It allows a state-changing request when `ALLOWED_ORIGIN` is unset or when the request carries no `Origin` header, so it only rejects a browser request from an origin it knows to be wrong. The production Compose file sets `ALLOWED_ORIGIN` from `APP_URL`; set it yourself on any other platform. See ADR-0008.
- **API rate limiting is fixed-window, not adaptive.** Defaults throttle general `/api/v1/*`, expensive sync/policy/connector-probe routes, and login by client IP and by email (complementing account lockout). The client IP is taken from `X-Forwarded-For` only when the TCP peer is in `KESTREL_TRUSTED_PROXIES`; when the web server is exposed without a reverse proxy in front, Next.js passes a browser-supplied `X-Forwarded-For` through unchanged, so the per-IP bucket can be spoofed there (the per-email bucket and lockout still hold). Redis-backed when available; see `docs/operations/rate-limiting.md`. Not a substitute for edge WAF / CDN limits.
- **No published or signed images.** Kestrel ships Dockerfiles only; operators build the images themselves, so image signing, SBOMs and provenance are theirs to add. Release tags are signed when the release key is configured.
- **No protection against malicious connector packages.** Since connectors are ordinary installed Python packages discovered via entry points, a malicious connector package has the same code-execution trust level as any other dependency — there's no sandboxing or capability restriction. This is a real gap for a "third-party connector ecosystem" future; today, only install connectors you trust, same as any Python dependency.
- **Analysts can set connector secrets.** The `analyst` role creates connector instances and enters their credentials, so an analyst account is a credential-bearing account, not a read-mostly one; the re-pointing defence above limits what a compromised analyst can do with secrets already stored, but not what they can store. Treat analyst accounts accordingly (MFA required, reviewed in the audit log).
- **Envelope encryption with a single root key, not a real KMS** (ADR-0004) — documented there and here again because it's the single highest-value asset in the system. Rows written by pre-release builds (before 0.4.0) carry no associated data until `kestrel secrets rotate` has run once after upgrading; `kestrel secrets status` counts them. Installs that started on 0.4.0 or later have none.

- **The policy sandbox shares a Unix user with the API and worker.** Custom policy code runs under RestrictedPython in a child process with time and memory limits and a stripped environment (no `KESTREL_MASTER_KEY`, `DATABASE_URL`, or provider credentials). The child still runs as the same Unix user as its parent, so code that escaped RestrictedPython could read the parent's environment through `/proc`, including `KESTREL_MASTER_KEY`, and anything else that user can read. Running the evaluator as a separate user or container is not implemented. Until it is, limit who can author custom policies (analyst and above), and harden the containers (read-only root filesystem, dropped capabilities, no new privileges).
- **API tokens have no scopes.** A token acts with its operator's full role until it expires or is revoked; it cannot mint further tokens. Issue automation tokens to a dedicated operator with the narrowest role that works, and set an expiry (1 to 365 days).
- **The finding handoff's `jira_base_url` parameter resolves any hostname.** The SSRF guard resolves the host to refuse private and metadata addresses, so any signed-in operator, `read_only` included, can make the API perform a DNS lookup for a name of their choosing and learn whether it resolves to a public address. No HTTP request is made to the host. This is a minor DNS oracle, not request forgery.
- **An expired mute or exception reopens before it is re-evaluated.** When a mute or exception expires, the finding returns to `open` and emits `finding.opened` (webhook and notifications) immediately, even if the condition has since gone away; the next policy evaluation then resolves it. Receivers can see an open shortly followed by a resolve.
- **The web build fetches fonts from Google.** `next/font/google` downloads Inter and JetBrains Mono at build time and self-hosts them, so browsers never contact Google, but building the web image needs network access to Google Fonts. An offline build has to vendor the fonts first.

- **Correlation is a heuristic, and a wrong join is a disclosure.** Identities are correlated across applications by email (high confidence) and by a display name that is unique within every application (medium confidence). Two different people sharing a rare full name across two applications and having no email on either would be merged, which would show one person the other's access on the identity page. The unique-per-application requirement makes this narrow, but it is a judgement call, not a proof. Every account row states how it was matched, so a reviewer can see which link is the weak one; `identity_links` is a derived table and can be rebuilt after correcting the underlying data.
- **Readiness and metrics endpoints are unauthenticated.** `/healthz`, `/readyz`, and `/metrics` answer without a token, and `/readyz` names which dependency is failing. That is operationally necessary and mildly informative to an attacker; restrict them at the network edge in production, as `/metrics` already documents.

## Priorities for closing these gaps

Roughly in order of risk reduction per unit of effort (see [`roadmap.md`](roadmap.md)): (1) ~~general API rate limiting~~ (shipped); (2) an email-based invite/password-reset flow; (3) KMS integration as an alternative `KeyProvider`; (4) signed releases; (5) SSO/SCIM.

## Reporting a vulnerability

See `SECURITY.md`.
