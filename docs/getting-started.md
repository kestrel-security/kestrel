# Getting started

Everything needed to run Kestrel, from a clean checkout to a browser with
findings in it — either with nothing but Docker, or as a development stack.
Contribution process lives in
[`../CONTRIBUTING.md`](../CONTRIBUTING.md); tests in [`testing.md`](testing.md).

## Docker only

The quickest way to try Kestrel, and the shape of a real single-host
deployment. It needs Docker with Compose v2 and nothing else.

```bash
git clone https://github.com/kestrel-security/kestrel.git && cd kestrel
cp deployments/compose/.env.example deployments/compose/.env
```

Set the three required values in `deployments/compose/.env`:

| Variable | Value |
|----------|-------|
| `KESTREL_MASTER_KEY` | `openssl rand -base64 32`. Encrypts stored connector credentials; back it up somewhere other than this host |
| `POSTGRES_PASSWORD` | Any long random string, e.g. `openssl rand -hex 24` |
| `APP_URL` | The URL you will open in the browser. `http://localhost:3000` locally |

Then build and start the stack, and create the first admin:

```bash
docker compose -f deployments/compose/docker-compose.yml up -d --build
docker compose -f deployments/compose/docker-compose.yml run --rm api \
  kestrel init --admin-email you@example.com
```

`up --build` builds the three images from the checkout, which takes several
minutes the first time; allow about 4 GB of free memory. Kestrel doesn't
publish images: the Dockerfiles in `deployments/docker/` are the build. A one-shot `migrate` service applies migrations before the API and
worker start.

`kestrel init` creates the organization and the admin operator and prints a
random password once. In the container it writes no `.env` and never uses the
published development password; pass `--admin-password` to choose your own, or
set `KESTREL_ADMIN_EMAIL` / `KESTREL_ADMIN_PASSWORD` with `-e` on the
`docker compose run` command (`KESTREL_ADMIN_EMAIL` can also live in
`deployments/compose/.env`, which the Compose file passes to the api service).

To load the fixture demo — four synthetic tenants and a drift timeline, no cloud
credentials:

```bash
docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel demo up
docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel demo change
```

Open `http://localhost:3000/login`. The web UI listens on `127.0.0.1` only; to
reach it from another machine, behind TLS, follow
[`deployment.md`](deployment.md#production-with-docker-compose--implemented).

To remove the demo, stop the stack, or start over:

```bash
docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel demo down --yes   # remove the demo tenants
docker compose -f deployments/compose/docker-compose.yml down      # stop the stack; data is kept
docker compose -f deployments/compose/docker-compose.yml down -v   # stop and delete all data
```

`demo down` keeps the organization, operators, policies, and installed packs,
so the next step from the demo is to add real integrations
([Connecting a real application](#connecting-a-real-application)). `down -v`
deletes the PostgreSQL, Redis, and Caddy volumes; keep `deployments/compose/.env`
(and its `KESTREL_MASTER_KEY`) or delete it too for a clean start.

The rest of this page covers the development stack.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.12+ | `.python-version` |
| [`uv`](https://docs.astral.sh/uv/) | current | Python workspace and lockfile |
| Node.js | 22+ | `.nvmrc` |
| `pnpm` | 10.x | `packageManager` in `package.json`; `corepack enable` installs it, or [install pnpm directly](https://pnpm.io/installation) on a Node build without corepack |
| Docker with Compose | v2 | PostgreSQL 16 and Redis 7, optionally the whole stack |
| `make` | any | Wraps the commands below |

## First run

```bash
git clone https://github.com/kestrel-security/kestrel.git && cd kestrel
make sync        # uv sync && pnpm install
make demo-up     # Postgres + Redis, migrations, admin, fixture tenants, drift timeline, API, worker, web
```

`make demo-up` is the same as:

```bash
bash scripts/demo-preflight.sh     # refuse to start if a demo port is held by a stray process
docker compose up -d postgres redis
uv run kestrel demo up             # migrations, .env, admin operator, four fixture tenants
uv run kestrel demo change         # replay the drift timeline so Changes has content
docker compose up -d --build api worker web   # rebuilds the images so they match the checkout
make demo-verify                   # kestrel demo verify: fail if a demo beat has no subject
```

Open `http://localhost:3010/login` and sign in with the local defaults. The
development stack publishes the web UI on `3010` rather than the Docker
deployment's `3000` so it does not collide with a host-run `next dev` or with
other projects (see [Ports](#ports)).

| Field | Value |
|-------|-------|
| Email | `admin@kestrel.local` |
| Password | `kestrel-dev-password` |

`kestrel demo up` and `make seed` use them so redeploys keep the same login.
They are development-only; never use them anywhere reachable from a network
you do not control. A bare `kestrel init` does not use them: it prints a random
admin password once unless you pass one, or opt into the local default:

```bash
uv run kestrel init                                # random password, printed once
uv run kestrel init --admin-email you@example.com --admin-password "a-strong-password-12+chars"
uv run kestrel init --dev-password                 # the local default above (checkout only)
```

### What `kestrel demo up` does

1. Creates `.env` from `.env.example` if it is missing, generating a random `KESTREL_MASTER_KEY`.
2. Applies database migrations.
3. Creates the single `Organization` row and the first admin operator if none exists.
4. Installs the first-party packs `github-posture`, `okta-posture`, `gws-posture`, `slack-posture`, and `cross-app`.
5. Generates four fixture-backed tenants (GitHub, Slack, Okta, Google Workspace) from one shared roster of synthetic people, syncs them, and evaluates policies so findings appear. No cloud credentials are involved.

Fixture-backed instances are labeled **(demo)** under Integrations. Try
searching `Grace` on `/explore`: one identity spans Okta, Slack, and GitHub
through email correlation, and the outbound view shows roles and access across
all of them from a single node.

### Seeing change detection

The first sync of each connector is the baseline, so **Changes** is empty until
something moves. Replay a drift timeline across the demo tenants:

```bash
uv run kestrel demo change
```

It promotes a member to organization admin, grants admin on a sensitive
repository, enables public repository creation org-wide, authorizes an
over-scoped third-party Slack app, promotes an Okta user to Super Administrator,
and mixes in a demotion and some membership churn, back-dated across a
three-month timeline (seven steps, the oldest about 74 days ago, on a baseline
dated 96 days back). Open `/changes`: the changes that matter rank above
routine ones.
Running `up` and `change` repeatedly on the same database stacks each cycle's
drift into the feed; reset with:

```bash
make demo-down                      # kestrel demo down --yes, then docker compose down
```

`kestrel init --seed` (`make seed`) is the smaller alternative: one
fixture-backed GitHub tenant, no drift timeline. Full detail on what the demo
generates is in [`demo.md`](demo.md).

### Cleaning up or starting over

```bash
make demo-down          # kestrel demo down --yes, then docker compose down
docker compose down -v  # also delete the development database volume
```

`kestrel demo down` removes the demo tenants and everything derived from them;
the organization, operators, policies, and installed packs stay. To move from
the demo to real tenants, run it and then follow
[Connecting a real application](#connecting-a-real-application). After
`docker compose down -v`, `make demo-up` rebuilds everything from scratch.

## Running the application

### Full stack in containers

```bash
make dev            # docker compose up --build
```

Starts PostgreSQL, Redis, the API, the worker (with the beat scheduler), and the
web UI. The API and worker images bind-mount `kestrel/`, `connectors/`, `packs/`,
and the app sources, so `uvicorn --reload` picks up Python edits without
`--build`. The web image does not hot-reload; run the Next.js dev server on the
host for UI work.

### Pieces on the host (recommended while coding)

Keep PostgreSQL and Redis in Docker and run the rest with reload:

```bash
docker compose up -d postgres redis

# Host processes do not read .env; the API and worker need the master key to
# encrypt and decrypt stored secrets (connector credentials, webhooks, SMTP, MFA).
export KESTREL_MASTER_KEY="$(grep '^KESTREL_MASTER_KEY=' .env | cut -d= -f2-)"
uv run uvicorn kestrel_api.main:app --reload --port 8010
uv run celery -A kestrel_worker.celery_app worker --beat -l info
API_URL=http://localhost:8010/api/v1 pnpm --filter kestrel-web dev
```

`--beat` embeds the scheduler that dispatches `schedule_cron` syncs; that is
fine for a single local process (see
[`operations/scheduled-syncs.md`](operations/scheduled-syncs.md)). The web dev
server uses `next dev --turbopack` and listens on `http://localhost:3000`
(the containerized `web` service is on `3010`). Stop the Compose `api`,
`worker`, and `web` services first so they do not shadow the host ports.

To run only `next dev` on the host against the Compose `api` instead, add
`ALLOWED_ORIGIN=http://localhost:3000,http://localhost:3010` to `.env` and
recreate the api container (`docker compose up -d api`). The Compose file
defaults the API's origin allowlist to `http://localhost:3010`, so a
state-changing request carrying the `:3000` origin is refused with
`403 Origin not allowed`. A host-run `uvicorn` does not read `.env` and leaves
the check off.

### Ports

Host ports are shifted so Kestrel does not collide with other projects on the
same machine, and every one is bound to `127.0.0.1` only: the development stack
has fixed credentials and is never reachable from the network:

| Service | Host | In-container |
|---------|------|--------------|
| Web | 3010 | 3000 |
| API | 8010 | 8000 |
| PostgreSQL | 5433 | 5432 |
| Redis | 6380 | 6379 |
| Worker metrics | 9101 | 9101 |

Container-to-container traffic uses the internal Docker network and the
unshifted ports (`api:8000`, `postgres:5432`). Host-side tools (the CLI,
Alembic, pytest) default to `localhost:5433` and `localhost:6380`. `.env` holds
the Compose service names and is **not** loaded by host tools; do not export
its `DATABASE_URL` into your shell. Remap ports in a gitignored
`docker-compose.override.yml` if needed. The comment in
`apps/web/src/lib/api.ts` explains why the web app's API base URL differs
between `next dev` on the host and the containerized `web` service.

## Configuration

Every variable is documented in [`../.env.example`](../.env.example). The ones a
real deployment must set (the same three the [Docker only](#docker-only)
section fills in):

| Variable | Purpose |
|----------|---------|
| `KESTREL_MASTER_KEY` | Base64 32-byte root key for stored-secret encryption; `openssl rand -base64 32`; back it up separately from the database. Rotate with `kestrel secrets rotate` ([`deployment.md`](deployment.md)) |
| `POSTGRES_PASSWORD` | Password for the bundled PostgreSQL; the Compose deployment builds `DATABASE_URL` from it |
| `APP_URL` | The origin browsers use, scheme included. Drives the `/login` redirect, the session cookie's `Secure` flag, and the API's allowed origin |

`DATABASE_URL`, `REDIS_URL`, and `API_URL` are derived inside both Compose
files (`postgres:5432`, `redis:6379`, `http://api:8000/api/v1` over the Docker
network) and only need setting when you run the images on your own platform;
host-side tools default to `localhost:5433` and `localhost:6380`.

Optional groups: observability (`KESTREL_METRICS_PORT`, `OTEL_*`), rate limiting
(`KESTREL_RATE_LIMIT_*`), default SMTP for notification email, watched-findings
digests and dashboard schedules (`KESTREL_SMTP_*`, overridden per org in
Settings → Email), an
LLM for policy drafts (`KESTREL_LLM_*`, overridden per org in Settings → AI),
the connector SSRF allowlist (`KESTREL_CONNECTOR_URL_ALLOWLIST`), and a
plugin directory for custom connectors (`KESTREL_CUSTOM_CONNECTORS_DIR`).

## Operators and API tokens

Admins invite teammates at `/settings/operators` or from the CLI:

```bash
uv run kestrel operator create teammate@example.com --role analyst
uv run kestrel operator list
uv run kestrel operator set-role teammate@example.com admin
uv run kestrel operator deactivate teammate@example.com

uv run kestrel token create --email teammate@example.com --name ci-pipeline
uv run kestrel token list --email teammate@example.com
uv run kestrel token revoke <token-id>
```

An invited operator should replace the password they were given at
**Settings → Account** (`/settings/account`, also reached by clicking your name
in the sidebar). Changing a password signs out every other session that
operator has open; API tokens keep working.

An admin resets someone else's password from **Settings → Operators → Reset
password**: Kestrel generates a temporary password (shown once, to hand over),
ends that operator's sessions, and by default revokes their API tokens. When no
admin can sign in, `uv run kestrel operator set-password <email>` does the same
from the CLI.

### Two-factor authentication

Any operator can turn on two-factor authentication at **Settings → Account**:
scan the QR code with an authenticator app (1Password, Google Authenticator,
and similar), enter a code, and save the ten single-use recovery codes. From
then on, signing in asks for a 6-digit code after the password; a recovery code
works in its place once.

An admin can require it for everyone with **Settings → Operators → Require
two-factor authentication**. Nobody is signed out; anyone without it is asked
to set it up at their next sign-in, before they can use anything else. If
someone loses their device, an admin uses **Reset MFA** on their row (or
`uv run kestrel operator reset-mfa <email>`), which also ends their sessions.
API tokens are not asked for a code, but an operator with two-factor
authentication can only create one from a signed-in session.

### API access

Every API request needs `Authorization: Bearer <token>`: the token from
`POST /auth/login` (what the web session cookie carries) or an API token.
There is no page for API tokens in the web UI; create them with the CLI:

```bash
# Development checkout
uv run kestrel token create --email you@example.com --name ci-pipeline --expires-in-days 90
# Docker deployment
docker compose -f deployments/compose/docker-compose.yml run --rm api \
  kestrel token create --email you@example.com --name ci-pipeline --expires-in-days 90
```

The token is printed once. `--expires-in-days` accepts 1 to 365; leave it out
for a token that does not expire. A signed-in session can also create one with
`POST /api/v1/api-tokens`, but an API token cannot create another token.

An API token acts with its operator's full role: there are no per-token
scopes, so issue it to an operator whose role is no broader than the
automation needs (often `read_only`), and revoke it with `kestrel token revoke`
when it is no longer used.

On the development stack the API is published on `localhost:8010`:

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8010/api/v1/findings
```

The Docker deployment publishes only the web UI, so the API has no host port
by default. To reach it, publish it on loopback with a Compose override, or
route `/api/v1/` to it from your reverse proxy; see
[Reaching the API with a token](deployment.md#reaching-the-api-with-a-token).

Roles are `read_only` (view everything), `analyst` (also change finding status
and ownership, create exceptions, manage connector instances and syncs), and
`admin` (also manage operators). Design: [ADR-0008](adr/0008-opaque-tokens-for-operator-auth.md).

## Connecting a real application

Live connectors are configured from Integrations → Add integration: paste the
credentials into the form, run **Test connection**, then **Sync**. Setup
guides per application live under [`connectors/`](connectors/). Credentials
are envelope-encrypted at rest and never belong in `.env` or in a repository.

For a custom connector whose API runs on a local address, the API must be
allowed to reach it: Compose already sets
`KESTREL_CONNECTOR_URL_ALLOWLIST=127.0.0.1,localhost,host.docker.internal`; on
the host, export the same value. See
[`connectors/authoring-tutorial.md`](connectors/authoring-tutorial.md).

## Everyday commands

| Command | Purpose |
|---------|---------|
| `make sync` | Install Python and Node dependencies |
| `make dev` / `make down` | Full container stack up / down |
| `make demo-up` / `make demo-down` | The whole demo environment up (containers, seed, drift timeline) / down |
| `make demo-change` | Replay the drift timeline again |
| `make seed` | `kestrel init --seed` (single fixture GitHub tenant) |
| `make migrate` / `make revision m="..."` | Alembic upgrade / autogenerate |
| `make lint` / `make format` | Ruff check + format check + mypy / apply formatting |
| `make test` / `make coverage` | pytest at `-n auto` / with the HTML coverage report |
| `make hygiene` | Secret scan + forbidden-string check (no secrets or personal identifiers) |
| `make docs-check` | Required docs exist and relative links resolve |
| `make validate` | Everything CI runs, in one command |

CLI highlights:

```bash
uv run kestrel --help
uv run kestrel sync --connector github --instance <id> --no-async   # same pipeline the worker runs, in-process
uv run kestrel policy validate examples/policies/my_first_policy.py
uv run kestrel policy test examples/policies/my_first_policy.py --fixtures examples/policies/my-first-policy.fixtures.json
uv run kestrel pack install packs/github-posture
uv run kestrel connector create my-app
uv run kestrel connector validate connectors/my-app
uv run kestrel audit list
uv run kestrel retention trim-raw-source --older-than-days 90
```

## Database migrations

```bash
make revision m="describe the change"   # uv run alembic revision --autogenerate
make migrate                            # uv run alembic upgrade head
uv run alembic upgrade head --sql       # render without a database (CI does this)
```

Migrations live in `migrations/versions/`. Prefer additive migrations; an
irreversible migration needs explicit maintainer approval.

## Optional services

- **Prometheus:** `docker compose --profile observability up` scrapes the API
  `/metrics` and the worker on `:9101`; open `http://localhost:9090`. See
  [`observability.md`](observability.md).
- **Adminer:** `docker compose --profile debug up -d adminer` serves a database
  browser on `http://localhost:8080` (server `postgres`, user `kestrel`,
  password `kestrel_dev`). Development stack only; it has no authentication of
  its own.
- **Rate limiting** is on by default for `/api/v1/*` (Redis-backed when
  `REDIS_URL` is reachable, in-memory otherwise). Tune with
  `KESTREL_RATE_LIMIT_*`; see [`operations/rate-limiting.md`](operations/rate-limiting.md).

## Troubleshooting

| Symptom | Likely fix |
|---------|------------|
| API 503 "No organization configured" | Run `uv run kestrel demo up` or `uv run kestrel init`; in the Docker deployment, `docker compose -f deployments/compose/docker-compose.yml run --rm api kestrel init --admin-email you@example.com` |
| Sign-in redirects to `localhost:3000` from another host | Set `APP_URL` to the URL the browser uses; see [`deployment.md`](deployment.md#behind-a-reverse-proxy--implemented) |
| Sign-in succeeds but loops back to `/login` over plain HTTP | The session cookie is `Secure` when `APP_URL` is `https`. Use HTTPS, or set `APP_URL` to the `http://` URL you actually use |
| Web cannot reach the API in Compose | `API_URL=http://api:8000/api/v1` (service DNS) |
| Web cannot reach the API on the host | `API_URL=http://localhost:8010/api/v1` |
| Tests fail connecting to the database | Start Postgres; `DATABASE_URL` must use host port `5433` |
| Port conflicts | Remap via a gitignored `docker-compose.override.yml` |
| `pnpm` refuses to start | `corepack enable`; the version comes from `packageManager` |
| `demo up` / `init`: "at a migration revision this checkout does not know" | The database on 5433 was created by another branch or checkout. Point `DATABASE_URL` elsewhere, or `make db-reset CONFIRM=yes` (destroys it) |
| `make demo-up`: "port 3010 is held by node (pid …)" | A host-run dev server (usually a leftover `uvicorn` or `next dev` from another checkout) holds a demo port. Stop it, or remap the port in a gitignored `docker-compose.override.yml`. The preflight names the process and its working directory |
| The demo UI is missing something that is on `main` | The containers are running images built from an older checkout. `make demo-up` rebuilds the `api`, `worker`, and `web` images every run (a no-op when nothing changed); a plain `docker compose up -d` reuses whatever image is already tagged |
| `docker compose up`: "Bind for 127.0.0.1:5433 failed: port is already allocated" | Another Compose project holds the port. The development project name is pinned to `kestrel` (the Docker deployment uses `kestrel-server`), so a second checkout of this repository shares the stack; anything else on 5433 must be stopped or remapped |

Reset the local database (destructive, local only):

```bash
make db-reset CONFIRM=yes      # DROP SCHEMA public CASCADE, then alembic upgrade head
```
