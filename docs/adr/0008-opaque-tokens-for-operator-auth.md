# ADR-0008: Opaque Tokens for Operator Authentication

## Status

Accepted. The `kestrel query` command named below was removed in 0.4.0; the
rest of the decision stands.

## Context

Kestrel's threat model documented the single highest-priority gap in the vertical slice: there was no authentication anywhere. `apps/api/src/kestrel_api/deps.py::get_current_org` did a blind `select(Organization).first()` — anyone who could reach the API or UI could see and mutate everything, with no notion of who they are. This blocks related platform concerns (audit attribution, approval workflows, SSO) and is unsafe to expose beyond localhost.

This needed to ship as a real capability of the self-hosted product: local email/password login, both browser sessions and long-lived API tokens from day one, a small fixed 3-role RBAC set (Admin, Analyst, Read-only), CSRF protection, and real user-attributed audit logging.

**Naming note**: a `User` model already exists (`kestrel/src/kestrel/db/models/identity.py`) representing a SaaS identity *discovered by a connector*, not a Kestrel login account. The "person who logs into Kestrel" concept is named `Operator` throughout, to avoid colliding with `User`/`Role`/`Permission`/`Group`/`Grant`, which already model discovered SaaS access data in the graph.

## Decision

- **Opaque, server-validated bearer tokens, not JWT.** `secrets.token_urlsafe(32)` generated, SHA-256-hashed before storage (a DB dump alone yields no usable credential), looked up via indexed equality against either `OperatorSession` (browser-driven) or `ApiToken` (CLI/automation) rows.
- **One uniform mechanism for both credential types.** FastAPI's `get_current_operator` dependency (`apps/api/src/kestrel_api/deps.py`) checks `Authorization: Bearer <token>` against `OperatorSession` first, then `ApiToken` — same header, same dependency, regardless of whether the caller is a browser or a CLI/automation client.
- **The browser/cookie concern lives entirely in Next.js, not FastAPI.** Kestrel's web app fetches data exclusively from Server Components/Server Actions (`apps/web/src/lib/api.ts`'s `API_URL` is server-only, never exposed to the browser bundle). On login, a Server Action calls `POST /auth/login`, gets an opaque token back in the JSON body, and sets it as an `httponly`/`secure`(prod)/`samesite=lax` cookie on the Next.js app's own domain. Every Server Component reads that cookie via `next/headers` and forwards it as a Bearer header. **FastAPI never sees or sets a cookie.**
- **Small fixed RBAC**: `OperatorRole` (`read_only`, `analyst`, `admin`) via an explicit rank dict (`kestrel/src/kestrel/auth/rbac.py`'s `_ROLE_RANK`), not enum declaration order — `role_satisfies(actual, minimum)` compares ranks.
- **Argon2id** (via `argon2-cffi`) for password hashing — current OWASP-recommended default, actively maintained, no bcrypt's 72-byte truncation footgun.
- **Login lockout**: 5 failed attempts locks an operator for 15 minutes (`kestrel/src/kestrel/auth/service.py`'s `LOCKOUT_THRESHOLD`/`LOCKOUT_DURATION`). `authenticate_operator` returns a uniform `None` for unknown-email, wrong-password, inactive, or locked — no user enumeration.
- **Sessions slide, but are capped.** `OperatorSession.expires_at` extends 24h on each use; `absolute_expires_at` is fixed at creation (30 days) and never extends, bounding how long a stolen-but-still-live token can be reused indefinitely.
- **Real, user-attributed audit logging** (`kestrel/src/kestrel/db/models/audit.py`'s `AuditLog`, written via `kestrel/src/kestrel/audit/service.py`'s `record_audit_event`) for login/logout/password changes, operator management, finding status changes and exceptions, and connector sync triggers — each row records `actor_operator_id`, not a free-text string.
- **CSRF is mostly a non-issue by construction**, not a bolted-on mitigation: a cross-site request can auto-attach a cookie but can't forge a custom `Authorization` header, so classic CSRF doesn't apply to FastAPI's actual auth mechanism. `OriginCheckMiddleware` (`apps/api/src/kestrel_api/middleware/origin_check.py`) is an opt-in (`ALLOWED_ORIGIN` env var), defense-in-depth backstop for the case FastAPI's port is ever accidentally reachable from a browser directly — a no-op by default in dev.

## Why not JWT

Revocation, "list active sessions," and lockout all require a DB hit anyway (an OperatorSession/ApiToken row has to exist and be checked), so JWT's main benefit — statelessness — doesn't apply here. A JWT would add signing-key lifecycle risk (rotation, algorithm confusion attacks) for no corresponding benefit, and would make instant revocation (e.g. "deactivate this operator right now") harder, not easier, since a JWT is valid until it expires unless you maintain a denylist — which is the same DB hit you'd need anyway.

## Consequences

- Every authenticated request costs one indexed DB lookup (hash equality on `token_hash`) — acceptable for Kestrel's expected request volume, and consistent with the rest of the API's per-request DB usage.
- `sync`/`query`/`init` CLI commands deliberately stay unauthenticated (they talk directly to Postgres via `DATABASE_URL`, already a stronger trust boundary than the network-facing API); only the API surface gets RBAC. `kestrel operator`/`kestrel token` are the CLI escape hatch for managing that RBAC before any web UI login even exists.
- Eventual SSO/SCIM/custom-RBAC/multi-org features are intended to stay additive on this same schema and dependency, not a redesign (see "Future extension points" below) — this was a hard design constraint for this ADR, not an afterthought.

## Future extension points (not built now — documented seams only)

- **SSO (SAML/OIDC)**: an additive `POST /auth/sso/callback` that finds-or-creates an `Operator` by `(org_id, email)` and calls the same `create_session()`. `password_hash` stays `NULL` for SSO-only operators — the column is already nullable for exactly this reason.
- **SCIM**: a `/scim/v2/Users` endpoint writing to the same `operators` table — another writer, not a parallel identity model.
- **Custom/fine-grained roles**: `OperatorRole` stays the fixed 3-value enum; a later nullable `custom_role_id` + `CustomRole`/`CustomPermission` tables could be consulted first by a `require_permission` check that falls back to `role_satisfies` for operators created under the fixed roles.
- **Multi-org**: email is unique per-org today (`UniqueConstraint("org_id", "email")`); multi-org gets its own migration later (same deferral precedent as ADR-0006), not solved here.
