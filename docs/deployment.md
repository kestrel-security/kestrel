# Deployment

How to run Kestrel somewhere other than a laptop. Labels mark each path
**implemented**, **experimental**, or **proposed**. Kestrel aggregates sensitive
posture data, so read [`../SECURITY.md`](../SECURITY.md) and
[`threat-model.md`](threat-model.md) before exposing it to a network.

## Paths

| Path | State | Where |
|------|-------|-------|
| Docker Compose, single host | Implemented, supported | `deployments/compose/` |
| Your own images on another platform | Bring your own | `deployments/docker/`; see [Building the images](#building-the-images) |
| Local development | Implemented | `docker-compose.yml` at the repository root; see [`getting-started.md`](getting-started.md) |

The root `docker-compose.yml` is the development stack: source bind mounts,
`uvicorn --reload`, every port published, a connector URL allowlist that
bypasses the SSRF guard for a local example, and the default development
database password. Do not deploy it.

## Production with Docker Compose — implemented

`deployments/compose/docker-compose.yml` runs the whole stack on one host:
PostgreSQL 16, Redis 7, a one-shot `migrate` service, the API, one worker with
the embedded beat scheduler, the web UI, and an optional Caddy in front.
Kestrel publishes no container images: `up --build` builds api, worker and web
from this checkout (see [Building the images](#building-the-images)) and tags
them `kestrel-{api,worker,web}:local`. To run a release, check out its tag.

```bash
cp deployments/compose/.env.example deployments/compose/.env    # then fill it in
docker compose -f deployments/compose/docker-compose.yml up -d --build
docker compose -f deployments/compose/docker-compose.yml run --rm api \
  kestrel init --admin-email you@example.com
```

`kestrel init` creates the organization and the first admin and prints a random
password once. Compose reads `deployments/compose/.env` automatically because it
sits next to the Compose file; keep it out of version control.

### Configuration

| Variable | Required | Purpose |
|----------|----------|---------|
| `KESTREL_MASTER_KEY` | Yes | Base64 of 32 random bytes (`openssl rand -base64 32`). Encrypts every stored connector credential, webhook signing secret, ticketing token, LLM API key, TOTP secret, and SMTP password |
| `KESTREL_MASTER_KEY_PREVIOUS` | During a rotation | The master key being retired, so rows it encrypted stay readable until `kestrel secrets rotate` re-encrypts them (below). Unset it afterwards |
| `POSTGRES_PASSWORD` | Yes | Password for the bundled PostgreSQL; the stack builds `DATABASE_URL` from it |
| `APP_URL` | Yes | The origin browsers use, scheme included. Drives the `/login` redirect and the session cookie's `Secure` flag (below), and is the API's `ALLOWED_ORIGIN` |
| `KESTREL_BIND_ADDRESS` | No | Host address the web UI listens on (default `127.0.0.1`) |
| `KESTREL_HTTP_PORT` | No | Host port for the web UI (default `3000`) |
| `KESTREL_DOMAIN` | With `tls` | Hostname Caddy obtains a certificate for |
| `KESTREL_COOKIE_SECURE` | No | Force the session cookie's `Secure` flag on or off instead of deriving it from `APP_URL` |
| `KESTREL_TRUSTED_PROXIES` | No | CIDRs the API accepts `X-Forwarded-For` from, so rate limits and audit records see the browser's IP rather than the web container's. Default: the private ranges Docker allocates networks from (below) |

Every other application variable has a working default and is documented in
[`../.env.example`](../.env.example). To set one, add it to
`deployments/compose/.env`: the Compose file loads that file into the
`migrate`, `api` and `worker` containers with `env_file`. Values the Compose
file sets itself (`DATABASE_URL`, `REDIS_URL`, `ALLOWED_ORIGIN`, ...) take
precedence over the file. The web container receives only `API_URL`, `APP_URL`
and `KESTREL_COOKIE_SECURE`. For a single-host deployment:

- **Leave `KESTREL_CONNECTOR_URL_ALLOWLIST` unset.** It is the documented bypass
  of the SSRF guard and exists for a local development example.
- **Webhook endpoints must be `https://`.** Deliveries carry an HMAC-signed
  finding payload, so the API refuses plain `http://` endpoint URLs on create
  and update, and the worker refuses to deliver to one (an `http://` endpoint
  saved by a pre-release build fails with a clear error until its URL is
  changed). The only
  exception is a host listed in `KESTREL_CONNECTOR_URL_ALLOWLIST`, for a local
  test receiver.
- **Set up email in Settings → Email** (notifications, the watched-findings
  digest, dashboard schedules): an admin enters the SMTP host, security,
  credentials and sender, and can send a test message. `KESTREL_SMTP_*`, which
  the Compose file passes to the API and worker, is an optional default for
  organizations that have not saved their own. Links in email use `APP_URL`.
  With neither, Kestrel sends no email and in-app notifications still work.
- **Never set `KESTREL_CELERY_TASK_ALWAYS_EAGER`.** It is test-only and runs jobs
  inline in the API process.
- First syncs of large tenants can outrun the worker's 1500-second soft limit.
  Raise `KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS` and
  `KESTREL_SYNC_TIME_LIMIT_SECONDS` together, not one alone.

### Network exposure and TLS

Only the web UI is published, on `127.0.0.1:3000` by default. The API, worker,
PostgreSQL, and Redis are reachable only on the Compose network. The web app
talks to the API server-side, so the API needs no public route.

To serve Kestrel on a hostname with a certificate, either:

- **Use the bundled Caddy.** Point DNS for `KESTREL_DOMAIN` at the host, open
  ports 80 and 443, set `APP_URL=https://<KESTREL_DOMAIN>`, and start with the
  profile. Caddy obtains and renews the certificate itself.

  ```bash
  docker compose -f deployments/compose/docker-compose.yml --profile tls up -d
  ```

- **Use your own reverse proxy** in front of `KESTREL_BIND_ADDRESS:KESTREL_HTTP_PORT`,
  and set `APP_URL` to the public origin (see [Behind a reverse proxy](#behind-a-reverse-proxy--implemented)).

#### Client IP and `KESTREL_TRUSTED_PROXIES`

Every browser request reaches the API through the web container, so the API's
TCP peer is always that container. The web server forwards the browser's
address in `X-Forwarded-For`, and the API believes the header only when the
peer is in `KESTREL_TRUSTED_PROXIES` (comma-separated CIDRs), reading it right
to left past trusted hops. The Compose file defaults it to
`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`, the ranges Docker allocates
networks from. Without it, every user shares one login rate-limit bucket and
one anonymous client could lock everyone out of sign-in.

- Put a reverse proxy (the bundled Caddy, or your own) in front of the web
  container. Next.js passes a browser-supplied `X-Forwarded-For` through
  unchanged when nothing in front of it sets one, so without a proxy the
  per-IP login bucket can be spoofed (the per-email bucket and account
  lockout still apply).
- If your users connect from private addresses, narrow the value to the
  Compose network's subnet (`docker network inspect kestrel-server_default`):
  a trusted range is skipped when reading the header.
- Unset (a bare `uvicorn` run) trusts no proxy and ignores the header.

The session cookie is marked `Secure` when `APP_URL` is `https`, so it is only
sent over TLS. With an `http://` `APP_URL` — evaluating on a LAN address, for
example — the cookie is sent over plain HTTP so sign-in works, and so does
everyone on that network's ability to read it. Use TLS for anything real.
`KESTREL_COOKIE_SECURE=true|false` overrides the derivation.

### Health checks

The API has two endpoints, and they are not interchangeable:

- `GET /healthz` — liveness. 200 as soon as the process is up, without checking
  any dependency.
- `GET /readyz` — readiness. Checks PostgreSQL and Redis; 200 with
  `{"status":"ready","checks":{...}}`, or 503 naming the failing dependency. The
  api image's `HEALTHCHECK` uses it, and the web service waits for it.

The web image's `HEALTHCHECK` requests `/login`. `/readyz` does **not** validate
`KESTREL_MASTER_KEY`: a wrong key reports ready and fails later, when a sync
decrypts a credential. After any key change or restore, run **Test connection**
on a connector to prove the whole chain. Keep `/healthz`, `/readyz`, and
`/metrics` off the public internet; they are unauthenticated by design.

### Exactly one worker

The worker runs Celery with the beat scheduler embedded, and beat dispatches
scheduled syncs, dashboard emails, and watched-findings digests. Run exactly one worker container: a second
would dispatch every schedule twice. Duplicate syncs are harmless (a
per-connector Redis lock serializes them); duplicate scheduled emails are not.
Scaling workers means running beat as its own single-replica service, which the
Compose file does not do.

Redis is the Celery broker, the result backend, the rate-limit store, and the
sync lock — a hard dependency, not a cache. The Compose file persists it with
append-only mode. Policy evaluation spawns a subprocess per batch and needs a
writable `/tmp`; do not run the containers with a fully read-only root
filesystem.

### Backups and recovery

Back up two things, and keep them apart:

1. **The database.**

   ```bash
   docker compose -f deployments/compose/docker-compose.yml exec -T postgres \
     pg_dump -U kestrel kestrel | gzip > kestrel-$(date +%Y%m%d).sql.gz
   ```

2. **`KESTREL_MASTER_KEY`**, somewhere other than this host. Without it a dump
   restores everything except stored connector credentials, which then have to
   be re-entered per connector. Without the database the key recovers nothing.

The per-credential encryption key is derived from the master key and the
organization's UUID, which lives in the database. So **restore into an empty
database before anything else runs**: do not run `kestrel init` first, because
it creates a new organization with a new UUID and the restored credentials will
no longer decrypt.

```bash
docker compose -f deployments/compose/docker-compose.yml up -d postgres
gunzip -c kestrel-YYYYMMDD.sql.gz | docker compose -f deployments/compose/docker-compose.yml \
  exec -T postgres psql -U kestrel kestrel
docker compose -f deployments/compose/docker-compose.yml up -d
```

Test a restore before you need one.

### Rotating the master key

Every stored secret records the id of the master key that encrypted it, so a
rotation is a re-encryption pass, not a restore. With the stack running:

1. Generate the new key: `openssl rand -base64 32`.
2. In `deployments/compose/.env`, set `KESTREL_MASTER_KEY_PREVIOUS` to the
   current key and `KESTREL_MASTER_KEY` to the new one.
3. Restart the API and worker so both hold both keys:
   `docker compose -f deployments/compose/docker-compose.yml up -d api worker`.
   New secrets are written with the new key from this point; old rows still
   decrypt with the previous one.
4. Re-encrypt everything under the new key:

   ```bash
   docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel secrets rotate
   docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel secrets status
   ```

   `status` must report every secret under the current key. The rotation is
   idempotent and safe to repeat; a row a request re-encrypted in the
   meantime is simply skipped.
5. Remove `KESTREL_MASTER_KEY_PREVIOUS` from `.env`, restart the API and
   worker again, and store the new key with your backups. The old key now
   decrypts nothing in this database.

If `status` reports secrets under a key this process does not hold, the
database was encrypted with a key that is neither `KESTREL_MASTER_KEY` nor
`KESTREL_MASTER_KEY_PREVIOUS`; set the previous key to it and rotate.

### Upgrades

```bash
git fetch --tags && git checkout vX.Y.Z      # the release to run
docker compose -f deployments/compose/docker-compose.yml up -d --build
```

The `migrate` service applies Alembic migrations, and the API and worker start
only after it exits successfully. Take a database backup first. Migrations are
additive by default; a release whose migration is not reversible says so in
[`../CHANGELOG.md`](../CHANGELOG.md).

**Pre-release installs only.** 0.4.0 was the first versioned release. An install
that started from a pre-release build (before 0.4.0) has stored secrets that
are not yet bound to the row they belong to. They keep working, but run the
one-time re-encryption after migrating so they gain that binding:

```bash
docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel secrets rotate
```

No key change is involved; `kestrel secrets status` shows how many rows are
still waiting, and reports none on an install that started on 0.4.0 or later. The migration's downgrade cannot undo a rotation, so take the
database backup first.

#### Running from your own repository

Some deployments keep a copy of a Kestrel release in their own repository,
next to material that is theirs: infrastructure code, private runbooks, deploy
workflows. Kestrel's documentation and hygiene gates (`scripts/docs-check.sh`,
`scripts/oss-hygiene.sh`) describe Kestrel's tree and would fail on that
material. List it in a `.downstream-paths` file at the repository root and both
gates skip it:

```text
# One path per line; a trailing slash means a directory.
.downstream-paths
infra/
runbooks/
```

The secret scan (gitleaks) is not affected and still covers every file.

## Behind a reverse proxy — implemented

Set **`APP_URL`** on the web container to the origin browsers use, scheme
included: `APP_URL=https://kestrel.example.com`.

The web container knows only the address it binds. Next's standalone server
builds the URL it hands middleware from `HOSTNAME`/`PORT`, so without `APP_URL`
the anonymous-request redirect to `/login` points at that internal address —
`https://localhost:3000/login` — which no browser can follow. Forwarding
`Host` and `X-Forwarded-Host` does not fix it, and the app deliberately does
not read them: both are attacker-controlled, and reflecting one into a
`Location` header is an open redirect. See `apps/web/src/lib/app-origin.ts`.

- It is read at startup, not compiled in, so one image can serve any host.
  The app resolves its public origin from `APP_URL` first and
  `NEXT_PUBLIC_APP_URL` second (both at runtime), so the latter is an optional
  fallback and a deployment that sets `APP_URL` can leave it unset
- The Compose deployment requires it in `deployments/compose/.env`; elsewhere,
  set it on the web container
- A value that is not an absolute `http(s)` URL is ignored with a warning on
  the web container's log, and the redirect falls back to the request's origin
- Verify after a release:

  ```bash
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://kestrel.example.com/
  # expect: 307 https://kestrel.example.com/login
  ```

## Building the images

Kestrel ships Dockerfiles, not images. Each one builds on a Docker Official
Image, and Dependabot keeps those tags current:

| Image | Dockerfile | Base | Runs |
|-------|------------|------|------|
| `kestrel-api` | `deployments/docker/api.Dockerfile` | `python:3.12-slim` | The API (port 8000); also migrations (`alembic upgrade head`) and `kestrel init` |
| `kestrel-worker` | `deployments/docker/worker.Dockerfile` | `python:3.12-slim` | Celery worker with embedded beat |
| `kestrel-web` | `deployments/docker/web.Dockerfile` | `node:22-slim` | Next.js web UI (port 3000) |

The supporting services use official images too: `postgres:16`, `redis:7-alpine`
and, for the `tls` profile, `caddy`.

Compose builds all three for you. To run Kestrel elsewhere, build from the
repository root (the build context) and push to your own registry:

```bash
git checkout vX.Y.Z
for image in api worker web; do
  docker build -f deployments/docker/$image.Dockerfile \
    -t registry.example.com/kestrel-$image:X.Y.Z .
  docker push registry.example.com/kestrel-$image:X.Y.Z
done
```

Add `--platform linux/arm64` (or use `docker buildx build --platform
linux/amd64,linux/arm64 --push`) for other architectures. All three images run
as a non-root user. On any platform:

- Run migrations with the api image (`alembic upgrade head`, or `kestrel init`
  on first install) before starting the API and worker. `kestrel init` looks
  for `alembic.ini` in the current directory and then in `/app` (where the
  image keeps it); set `KESTREL_ALEMBIC_INI` to point it elsewhere
- Run exactly one beat scheduler. The worker image's default command embeds
  it; to scale out, override the command on extra workers to drop `--beat`
  (see [Exactly one worker](#exactly-one-worker))
- Supply the variables in [Configuration](#configuration) yourself, plus
  `DATABASE_URL` and `REDIS_URL`, and set `APP_URL` on the web container
- Browsers talk only to the web container, which calls the API at `API_URL`
  (e.g. `http://api:8000/api/v1`). Expose the API's `/api/v1` yourself only if
  API-token clients need to reach it
  ([Reaching the API with a token](#reaching-the-api-with-a-token))

## Reaching the API with a token

API tokens are created with the CLI (there is no web page for them):

```bash
docker compose -f deployments/compose/docker-compose.yml run --rm api \
  kestrel token create --email you@example.com --name ci-pipeline --expires-in-days 90
```

The token is printed once. `--expires-in-days` accepts 1 to 365; omit it for a
token that never expires. A token carries its operator's full role, with no
per-token scopes, and cannot be used to create another token
(`POST /api/v1/api-tokens` requires a signed-in session). Give automation its
own operator with the narrowest role that works, and list or revoke tokens
with `kestrel token list --email ...` and `kestrel token revoke <id>`.

The Compose deployment publishes only the web UI, so a token client needs a
route to the API. Either:

- **Publish the API on loopback** with a `docker-compose.override.yml` next to
  the Compose file (Compose merges it automatically), then call
  `http://127.0.0.1:8000/api/v1/...` from the host or through an SSH tunnel:

  ```yaml
  # deployments/compose/docker-compose.override.yml
  services:
    api:
      ports:
        - "127.0.0.1:8000:8000"
  ```

  Keep the binding on `127.0.0.1`. A client connecting through a published
  port can appear to come from a Docker gateway address, which falls inside
  the default `KESTREL_TRUSTED_PROXIES` ranges, so the API would believe the
  `X-Forwarded-For` header it sends.

- **Route `/api/v1/` through your reverse proxy.** With the bundled Caddy, wrap the
  routes in `handle` blocks in `deployments/compose/Caddyfile`, so
  `https://<KESTREL_DOMAIN>/api/v1/...` reaches the API and everything else
  the web UI. Route only `/api/v1/`: the API's `/metrics` is unauthenticated.

  ```caddyfile
  {$KESTREL_DOMAIN} {
  	encode zstd gzip
  	handle /api/v1/* {
  		reverse_proxy api:8000
  	}
  	handle {
  		reverse_proxy web:3000
  	}
  }
  ```

## Air-gapped / restricted — proposed pattern

- Fixture mode, with the images built inside the restricted network or copied in
- No hard dependency on AI providers; the LLM settings are optional
- Kestrel publishes no images; you build, scan and sign your own

## Observability

- See [`observability.md`](observability.md)
- Prometheus: API `/metrics`, worker on `KESTREL_METRICS_PORT` when set. Both are
  unauthenticated; scrape them from inside the network
- Development: `docker compose --profile observability up` (Prometheus UI on `:9090`);
  `docker compose --profile debug up -d adminer` adds Adminer, a database
  browser, on `:8080` (development stack only)
- Optional OTLP tracing via `OTEL_EXPORTER_OTLP_ENDPOINT`
- Structured JSON request logs go to stdout; request bodies are never logged

## High availability — proposed

- Multi-replica API behind a load balancer, a separate single-replica beat,
  managed PostgreSQL, and highly available Redis
- Not provided turnkey by the Compose file today
- The rate limiter already uses Redis when `REDIS_URL` is set (backend `auto`),
  so the limit is shared across API replicas; set
  `KESTREL_RATE_LIMIT_BACKEND=redis` to make that a requirement rather than a
  fallback
