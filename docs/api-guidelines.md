# API Guidelines

Align with the **existing** FastAPI surface (`apps/api`, `docs/api.md`). Where practice lags the guideline, the gap is labeled.

## Versioning

- Prefix: `/api/v1`
- Breaking changes require a new version prefix or negotiated compatibility window
- OpenAPI available at `/openapi.json` and `/docs`

## Authentication

- **Current:** bearer token (`OperatorSession` / `ApiToken`); `POST /auth/login` unauthenticated; `GET /healthz` and `GET /metrics` public
- Document auth scheme in OpenAPI

## Authorization

- All tenant data scoped by `org_id` from `get_current_org`
- 404 for cross-org or missing resources (do not leak existence across tenants when multi-org exists)

## Tenant scoping

- Default: single org per deployment
- Do not add global unscoped list endpoints

## Pagination

Implemented for `GET /identities` and `GET /findings`.

- **Params:** `limit` (default 50, max 200 — larger values are clamped, not rejected; `limit < 1` is `422`) and `cursor` (opaque).
- **Response:** `{"items": [...], "next_cursor": "..."}`. `next_cursor` is `null` on the last page; pass it back as `?cursor=` to fetch the next.
- **Sort:** always `(<timestamp> DESC, id DESC)` — `last_seen_at` for findings, `created_at` for identities. The `id` tiebreaker is required: timestamps collide routinely (one sync writes many rows in a single transaction), and without it a page boundary would skip or repeat the colliding rows.
- **Keyset, not offset:** offset pagination silently drops or duplicates rows when the underlying set changes between fetches, which for a continuously-syncing inventory is normal rather than exceptional.
- Cursors are opaque base64url JSON. Clients must not parse them; the encoding may change without a version bump.
- A malformed cursor is `422`, never a silent fall-back to an unpaginated scan.
- Filters must be SQL predicates, applied before `LIMIT`. A filter applied in Python after fetching would return short pages while matches remained.
- Endpoints not yet paginated (`/applications`, `/policies`, `/connector-instances`, `/compliance/controls`) return bare arrays; they are bounded by connector/pack count in practice.

## Filtering and sorting

- Use query params (`status`, `severity`, `search`, …)
- Reject unknown filter values with 422
- Document default sort order

## Idempotency

- Sync triggers should be safe to retry (pipeline upserts are idempotent)
- Proposed: `Idempotency-Key` for mutate endpoints that create resources

## Error format

- FastAPI/Pydantic `422` validation errors
- `404` not found / not in org
- `503` when uninitialized (no Organization)
- Prefer `{ "detail": ... }` consistency; evolve to problem+json only with an ADR

## Correlation IDs

- **Proposed:** accept/generate `X-Request-ID`, echo in response and logs

## Rate limiting

Implemented. Fixed-window limits on `/api/v1/*` (auth-aware default / expensive / login tiers). See `docs/operations/rate-limiting.md`. Restrict `/metrics` at the network edge.

## Deprecation

- Announce in changelog + OpenAPI `deprecated`; keep ≥ one minor/cycle

## Auditability

- Mutating endpoints should emit audit events

## OpenAPI expectations

- Keep response models typed (Pydantic)
- `/docs` is source of truth for wire shapes; `docs/api.md` is the human map

## Webhook conventions

- Signed payloads (`X-Kestrel-Signature: v1=<hmac-sha256>`, `X-Kestrel-Timestamp`), ±5 minute receiver tolerance recommended
- Per-org endpoints (`/api/v1/webhooks`), admin-managed
- Event types: `finding.opened`, `finding.resolved` (v1)
- SSRF guard on endpoint URLs (same helper as connector config)
- Delivery async via Celery; history on `webhook_deliveries`
