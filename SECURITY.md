# SECURITY.md — Security Policy and Secure Development

## Reporting a vulnerability

If you believe you've found a security vulnerability in Kestrel, **do not open a public GitHub issue**. Instead:

1. Use [GitHub private vulnerability reporting](https://github.com/kestrel-security/kestrel/security/advisories/new) (Security → Report a vulnerability). Only the maintainers can see the report. Include a description, reproduction steps, and potential impact. If private reporting is unavailable to you, open a minimal public issue that says you have a security report, with no details of the vulnerability. A maintainer will open a draft security advisory and add you as a collaborator, so the report and the fix are discussed privately on GitHub. There is no email channel.
2. Include the version/commit tested.
3. Allow a reasonable window for a fix before public disclosure. We aim to acknowledge reports within **5 business days** and to have a remediation plan within **30 days** for confirmed issues.

We credit reporters in release notes for confirmed vulnerabilities unless anonymity is requested.

### Scope

**In scope:** `kestrel` core, `apps/api`, `apps/worker`, `apps/web`, bundled connectors (`connectors/`), the Dockerfiles and Compose files in this repository.

**Out of scope (still worth reporting if bundled):** third-party connectors built with the SDK — connectors are unsandboxed Python (see threat model). A malicious connector is a supply-chain risk akin to any untrusted dependency.

### Supported versions

Kestrel is pre-1.0. Security fixes land on `main` and ship in the next release; only the latest release is supported. Upgrade rather than backport.

---

## Known limitations (current)

Documented in detail in `docs/threat-model.md`:

- Envelope encryption with a single root key (not KMS)
- No published or signed container images; operators build their own
- No connector sandboxing
- The policy sandbox runs as the same Unix user as the API and worker
- API tokens carry the operator's full role (no per-token scopes)

Login attempts are throttled via account lockout **and** two rate-limit buckets, one per client IP and one per email. General `/api/v1/*` traffic is also rate-limited (per authenticated credential, otherwise per client IP); the client IP comes from `X-Forwarded-For` only when the peer is in `KESTREL_TRUSTED_PROXIES`. See `docs/operations/rate-limiting.md`.

These are known gaps, documented in [`docs/threat-model.md`](docs/threat-model.md) and [`docs/roadmap.md`](docs/roadmap.md). Exploit paths worse than documented should still be reported.

---

## Secure development expectations

- Treat connector credentials and collected SaaS data as **highly sensitive**
- Prefer parameterized queries / ORM; never string-concatenate user input into SQL
- Validate and normalize untrusted input at API boundaries (Pydantic)
- Do not log secrets, tokens, or raw credential fields; use `kestrel.secrets.store.redact`
- Do not commit `.env`, keys, or tenant data
- Do not disable authz, TLS, or encryption to “make tests pass”
- Add or update tests for security-sensitive changes
- Consider tenant scoping (`org_id`) on every new query
- Document new threats or controls in the threat model when behavior changes

## Secrets handling

- Local secrets live in `.env` (gitignored); start from `.env.example` placeholders only
- `KESTREL_MASTER_KEY` protects connector secrets at rest — treat as production-critical
- Never print master keys or connector tokens in CI logs, session logs, or issues
- Automated tooling, including AI coding assistants, must not transmit secrets to unrelated external services

## Repository hygiene

- `scripts/oss-hygiene.sh` (also `make hygiene`) runs gitleaks and a denylist of strings that must never appear in this repository; CI runs it on every PR
- `.gitleaks.toml` allowlists only documented false positives; never add an entry to hide a real credential — rotate it first
- The contributor-facing rules are in [`CONTRIBUTING.md`](CONTRIBUTING.md#code-conventions)

## Dependency security

- Prefer pinned lockfiles (`uv.lock`, `pnpm-lock.yaml`)
- Review new dependencies for maintenance, license, and privilege surface

### Scan policy (blocking)

Every scan **fails its run** rather than reporting advisory output. They are split by cost:

| Scan | Where it runs | Gate |
|------|---------------|------|
| `scripts/audit-python.sh` (locked Python workspace) | `security-scan.yaml`: every PR, pushes to `main`, weekly, releases | Any known advisory fails |
| `pnpm audit --audit-level=high` (Node) | `security-scan.yaml`: every PR, pushes to `main`, weekly, releases | High/critical fails |
| gitleaks (full history) | `security-scan.yaml`: every PR, pushes to `main`, weekly, releases | Any finding fails |
| Trivy (`api`/`worker`/`web` images) | `nightly.yaml` (daily, manual and releases) | CRITICAL/HIGH **with a released fix** fails |

The image scans rebuild all three images from the Dockerfiles, so they are not on the pull-request path. Kestrel publishes no images: the nightly scan shows what a self-hoster's own build of that commit would carry, and a fixable finding is treated as a release blocker.

Trivy uses `ignore-unfixed: true`: a base-image CVE with no available patch is not something a change in this repository can resolve, so blocking on it would only train people to ignore the gate. Fixable findings block.

**Resolving a finding, in order of preference:**

1. **Fix it** — bump the dependency, or change the base image.
2. **Override a transitive pin** — when a direct dependency pins a vulnerable range of something it depends on, force the patched version via pnpm `overrides` (see `pnpm-workspace.yaml`; `sharp` and `postcss` are pinned this way today because `next` pins vulnerable ranges of both). Remove the override once upstream catches up.
3. **Suppress, with a written reason** — container findings in `.trivyignore`, and npm advisories with no patched release in `auditConfig.ignoreGhsas` in `pnpm-workspace.yaml` (today: one `braces` advisory reachable only through build tooling). Every entry needs a justification and a removal condition. Never suppress a finding in code this repository owns.

Run the same checks locally before pushing:

```bash
bash scripts/audit-python.sh
pnpm audit --audit-level=high
```

## Authentication expectations

**Current:** implemented (ADR-0008). Every `/api/v1/*` route requires `Authorization: Bearer <opaque token>`, checked against `OperatorSession` (browser login) or `ApiToken` (CLI/automation) rows via `get_current_operator`; `/healthz`, `/readyz`, and `/metrics` remain public (restrict `/metrics` at the network edge in production — see `docs/observability.md`). Passwords are hashed with Argon2id; login lockout (5 failed attempts, 15-minute lock, counted atomically in the database) and uniform failure responses resist brute-forcing and user enumeration: unknown, inactive and locked accounts run one Argon2 verification against a dummy hash, so they take as long as a wrong password. Changing a password signs out the operator's other sessions; an admin reset (`POST /operators/{id}/set-password`) revokes all of the operator's sessions and, unless `revoke_api_tokens: false`, their API tokens. **Target (not yet built):** SSO/SCIM as an additive extension on the same schema — see ADR-0008.

## Authorization principles

- Deny by default: every route requires a valid operator; unauthenticated requests get `401`
- Scope every data access by organization (`get_current_org`)
- Read vs mutate privileges are separated via a fixed 3-role RBAC set (`read_only` < `analyst` < `admin`, `require_role`)
- Later fine-grained roles must not break local-admin usefulness for single-org deployments

## Tenant isolation

- Every tenant-owned table includes `org_id` (ADR-0006)
- Application-layer filtering is mandatory; Postgres RLS is proposed defense-in-depth
- Cross-org leakage is covered by regression tests (`tests/integration/test_api_tenant_isolation.py`)

## Encryption expectations

- Stored secrets (connector credentials, webhook signing secrets, ticketing tokens, LLM API keys, TOTP secrets, SMTP passwords): AES-256-GCM at rest with a per-org key derived from `KESTREL_MASTER_KEY`; every ciphertext is bound to its table, row, and field through associated data, so a ciphertext copied onto another row fails to decrypt
- Master-key rotation: `KESTREL_MASTER_KEY_PREVIOUS` plus `kestrel secrets rotate` re-encrypts every row under the new key; `kestrel secrets status` shows which key wrote each row (`docs/deployment.md`)
- TLS in transit for deployed environments (terminate at ingress/proxy)
- Proposed: KMS/Vault `KeyProvider`

## Audit logging

- Request logging: method/path/status/duration (no bodies), including `operator_id`
- Entity change `events` from sync upserts
- `audit_log` rows with a real `actor_operator_id` for sensitive mutations (finding status/assignment changes, exceptions, connector-instance create/sync-trigger, operator create/update/set-password, login/logout)
- Readable via `GET /audit-log` (admin-only, cursor-paginated) and `kestrel audit list`

## Input validation

- Pydantic models on API boundaries
- Python policies compiled/validated (RestrictedPython) before evaluation
- Connector manifests validated via SDK

## Connector credential handling

- Secrets stored only in `connector_secrets`, never inline in instance config JSON
- Decrypt only when authenticating a live run
- Redact secret fields from logs and API responses
- Credentials never follow a connector to a new host: changing a URL / host config field (`org_url`, `base_url`, any `*_url`, `*_uri`, `*_host`, `*_domain` key, or any URL-valued key) through `PATCH /connector-instances/{id}` or `kestrel apply` clears the stored secrets unless new ones arrive in the same request, and the audit event records it. The Jira integration's `base_url` and the org LLM provider / `base_url` follow the same rule: the token or API key must be re-entered with the change
- Live-mode URLs that receive credentials must use `https` (plain `http` only for hosts on `KESTREL_CONNECTOR_URL_ALLOWLIST`)
- Okta: `org_url` must be on an Okta-owned domain (`*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com`, `*.okta-gov.com`, `*.okta.mil`); a custom Okta domain works only when the deployment operator adds it to `KESTREL_CONNECTOR_URL_ALLOWLIST`

## Webhook validation

- Implemented: outbound finding webhooks with HMAC signatures (`X-Kestrel-Signature: v1=<hmac-sha256>`), timestamps (`X-Kestrel-Timestamp`), and tenant-bound endpoints
- Receivers should reject signatures outside a ±5 minute window; see `docs/api.md`

## Supply-chain security

- Install only trusted connectors (same trust as Python deps)
- Blocking image scans are implemented (see "Scan policy" above); Kestrel publishes no images, so signing and SBOMs are up to whoever builds them

## SSRF protections

- Implemented: `kestrel.security.ssrf.validate_connector_url` / `validate_connector_config_urls` resolve the hostname of any `http(s)://` URL in connector-instance config and reject every address that is not globally routable (`not ip.is_global`: private, loopback, link-local including cloud metadata `169.254.169.254`, CGNAT `100.64.0.0/10` including Alibaba Cloud's `100.100.100.200`, documentation and benchmarking ranges) plus reserved, multicast and unspecified ones. Known metadata addresses (`100.100.100.200`, `fd00:ec2::254`, `168.63.129.16`, `192.0.0.192`) are refused even for allowlisted hosts
- Applied at two points: `POST /connector-instances` (rejects unsafe config at create time, `400`) and `LiveHTTPTransport.__init__` (defense-in-depth, immediately before any real HTTP client is constructed — covers every current and future connector using the SDK's live transport, not just ones that remember to validate)
- Best-effort, not a network-level control: it resolves DNS once and the resolved address is not pinned for the connection that follows, so a DNS-rebinding attacker who changes a record's answer between validation and connect is a known residual risk (the window is small: webhooks, Jira and the live transport validate immediately before sending)
- `FixtureTransport` never makes real network calls and is unaffected — fixture-mode tests need no network access

## Injection protections

- SQLAlchemy parameterization; bound params in raw CTEs
- Avoid shelling out with user-controlled strings
- Treat policy text as data for parsing — not `eval`
- CSV exports (findings, blast radius, audit log, dashboards) prefix any cell starting with `=`, `+`, `-`, `@`, tab or carriage return with `'`, so SaaS-controlled text such as a display name cannot run as a spreadsheet formula (`kestrel.security.csv_safe`)

## Rate limiting and abuse prevention

- Implemented: fixed-window Redis/memory middleware on `/api/v1/*`; login lockout is separate. Requests are keyed by bearer token only after that token has authenticated, so random tokens cannot mint fresh buckets; everything else is keyed by client IP. Set `KESTREL_TRUSTED_PROXIES` to the web server / ingress networks so the client IP is the browser's, not the proxy's. See `docs/operations/rate-limiting.md`
- Connectors should respect provider rate limits with backoff (connector responsibility + SDK guidance)

## Secure defaults

- Fixture mode for demos without cloud credentials
- Encryption required for stored connector secrets
- No default admin login: the first admin's password is random and printed once unless one is given explicitly (the published development password is opt-in, for local checkouts only)

## Data retention

- `raw_source` and findings evidence may contain sensitive SaaS data — provider payloads routinely carry more detail than the normalized columns
- `raw_source` payloads can be redacted on a retention window with `kestrel retention trim-raw-source --older-than-days N` (entities, graph, and findings are preserved; only the payload is tombstoned). No default window and nothing runs automatically — retention length is a compliance decision. See `docs/operations/data-retention.md`.
- `events`, `audit_log`, and `connector_runs` have no automated cleanup; trim manually per the same doc, noting that `audit_log` is often the table you are required to retain longest
- Backups of Postgres imply backups of secrets ciphertext and posture data — protect backup media

## Backup and recovery

- Compose volume `pgdata` is the local DB
- Operators should document backup/restore before production use
- Test migrations on copies; avoid irreversible migrations without human approval

## Incident-response expectations

1. Rotate a compromised `KESTREL_MASTER_KEY` with `kestrel secrets rotate` (runbook in `docs/deployment.md`) and re-issue connector credentials at the provider (human-operated)
2. Revoke exposed SaaS tokens at the provider
3. Preserve audit/sync logs for forensics
4. Assess tenant data exposure; notify affected operators as appropriate
5. Patch and disclose per severity
