# API rate limiting

Authenticated and unauthenticated `/api/v1/*` requests are throttled with a
**fixed window** counter. Defaults are safe for interactive SecOps use; raise
or lower them via environment variables for automation-heavy deployments.

## Behavior

| Tier | Applies to | Default | Key |
|------|------------|---------|-----|
| `default` | Most `/api/v1/*` | **300 / 60s** | Hash of a bearer token that has already authenticated, else client IP |
| `expensive` | `POST` to: sync enqueue (`/connector-instances/{id}/sync`), policy validate / test / dry-run / evaluate / fixtures-from-matches (including the `-draft` variants), the connector probe (`/connectors/probe`; `test-connection` on an instance is `default`), and the SMTP test (`/settings/email/test`) | **30 / 60s** | Same as default |
| `login` | `POST /auth/login` | **20 / 60s** | Two buckets: client IP (middleware) and normalised email (login route); complements per-account lockout |
| exempt | `/healthz`, `/metrics`, OpenAPI UI | n/a | not counted |

When a limit is exceeded the API returns **429** with:

- JSON body: `{ detail, tier, limit, retry_after_seconds }`
- `Retry-After` (seconds)
- `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset`

Successful responses in a limited tier also include the `X-RateLimit-*` headers.

**Why tokens are not trusted before authentication.** The middleware runs
before the auth dependency. Keying on every distinct `Authorization` value
would let a caller send a fresh random token per request and never be
throttled, so a token gets its own bucket only after `get_current_operator`
has accepted it (remembered per process for five minutes); until then, and
for invalid tokens, the request counts against the client IP.

**Per-email login bucket.** The login route also counts attempts per
normalised (trimmed, case-folded) email, stored as a SHA-256 key. One account
cannot be guessed at faster than the limit from many addresses, and one noisy
address no longer blocks everyone else's sign-in. Exceeding it returns 429
with `Retry-After`.

**Backend:** Redis when `REDIS_URL` is reachable (`KESTREL_RATE_LIMIT_BACKEND=auto` default); otherwise an in-process memory store (single-worker only). Store errors **fail open** (request allowed, warning logged) so a Redis blip does not take the API down. Account lockout on failed login remains independent (see `kestrel.auth.service`).

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `KESTREL_RATE_LIMIT_ENABLED` | `true` | Set `0`/`false` to disable |
| `KESTREL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed window length |
| `KESTREL_RATE_LIMIT_DEFAULT` | `300` | General API limit per window |
| `KESTREL_RATE_LIMIT_EXPENSIVE` | `30` | Sync enqueue / policy test / connector probe / SMTP test |
| `KESTREL_RATE_LIMIT_LOGIN` | `20` | Login attempts per IP per window |
| `KESTREL_RATE_LIMIT_BACKEND` | `auto` | `auto` \| `redis` \| `memory` |
| `KESTREL_TRUSTED_PROXIES` | (unset: trust none) | Comma-separated CIDRs whose `X-Forwarded-For` is believed. The Compose deployment sets the private ranges |
| `REDIS_URL` | (compose/dev) | Shared with Celery; used when backend is redis/auto |

## Ops notes

- The API is always behind a proxy (the web server, an ingress). Set `KESTREL_TRUSTED_PROXIES` to those networks or every IP bucket collapses to the proxy's address. The header is read right to left and only from trusted peers; the web server forwards the browser address it received (see `apps/web/src/lib/api.ts`), so keep a reverse proxy in front of it. Details: [`../deployment.md`](../deployment.md).
- The memory backend sweeps expired windows every 30 seconds, so a stream of distinct client IPs cannot grow it without bound.
- Multi-replica API deployments should use Redis (`auto`/`redis`) so counters are shared.
- Login lockout (5 failures → 15 minutes) is still the primary credential-stuffing brake; the login tier limits IP-wide spray across many emails.
