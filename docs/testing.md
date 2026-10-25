# Testing

How Kestrel is tested: the rules every test is written against, the tiers, the
harness, and the commands. Every test in the repository follows this document,
and reviews are run from its checklist.

## Why the rules exist

The previous suite reached about 770 tests and failed on effectively every
pull request. Every failure traced to one mistake: tests asserted on content
that belonged to the product, not to the test. Tests named demo-fixture
personas and hard-coded pack paths, so renaming a demo user or reorganizing a
pack broke dozens of unrelated tests at once, nobody owned the breakage, and red
became the normal color. The suite was rebuilt on the rules below, against a
baseline measured on the old suite.

## The six rules

1. **Tests own their data.** Rows come from the factories in `kestrel.testing`. A test that needs an admin without MFA builds one; it does not look for one in shipped demo fixtures.
2. **Shipped fixtures get contract tests, not content assertions.** Per connector, exactly one test asserts that the fixture set normalizes cleanly, discovers every object type the manifest declares, and covers every change class it claims. No other test names a fixture persona.
3. **Packs are self-covering.** One parametrized sweep over `packs/*/policies/*.py` asserts each policy compiles and passes its own `.fixtures.json`. Adding a pack adds coverage; deprecating one breaks nothing.
4. **No shared mutable state.** No assertions against the process-global Prometheus registry; no `app.dependency_overrides` mutation from a test body; no singleton reconfiguration that outlives a test.
5. **No test touches the repository.** Writes go to `tmp_path`. Nothing opens `REPO_ROOT/.env`.
6. **Parallel-safe by construction.** A test that cannot run under `-n 4 -p randomly` is a bug in the test, not a reason to serialize the suite.

## Tiers

| Tier | Marker | Where | Contents | Budget | Gate |
|------|--------|-------|----------|--------|------|
| 0 Static | — | — | ruff check + format, mypy, `alembic upgrade head --sql`, `kestrel connector validate`, docs and version checks | ~45s | PR |
| 1 Unit | `unit` | `tests/unit/` (connectors in `tests/unit/connectors/`), `examples/*/tests/` | Pure logic. No DB, no network, no subprocess. | <60s | PR |
| 2 Integration | `integration` | `tests/integration/` | API via `TestClient`, services against a real session, sync with fixture transports | <3 min at `-n auto` | PR |
| 3 System | `system` | `tests/system/` | CLI end-to-end on an isolated database, migration replay | ~15 min | post-merge + nightly |
| 4 Live | `live` | anywhere | Real-tenant smoke; needs credentials | n/a | manual; skipped unless `KESTREL_RUN_LIVE_TESTS=1` |

Markers are applied by the tier `conftest.py` files and the root `conftest.py`;
a test file never declares its own tier. The PR gate is Tiers 0–2 in parallel
jobs, under five minutes total (`.github/workflows/ci.yaml`); Tier 3 and the
container image scans run in `nightly.yaml`, also called by the release gate
alongside the dependency and secret scans. Every release gate tests the tagged
commit before a GitHub Release is created.

## Commands

```bash
uv run pytest -n auto -q                             # everything (Tier 4 gated off); per-worker databases
uv run pytest -m unit -q                             # Tier 1 only, no Postgres needed
uv run pytest -m "unit or integration" -n auto -q    # the PR gate
uv run pytest -m system -q                           # Tier 3

KESTREL_ASSERT_NO_DB=1 uv run pytest -m unit -q      # Tier 1 purity, enforced
uv run pytest -n 4 -p randomly --randomly-seed=1234 -q   # order independence: two seeds must agree
uv run pytest -n 4 -p randomly --randomly-seed=9876 -q
uv run pytest -m "unit or integration" -n auto --durations=25 -q   # time budget, measured
uv run pytest -q; git status --porcelain                # repository cleanliness: must print nothing

uv run ruff check . && uv run ruff format --check . && uv run mypy kestrel/src apps/api/src apps/worker/src connectors
pnpm --filter kestrel-web lint && pnpm --filter kestrel-web typecheck && pnpm --filter kestrel-web test:unit && pnpm --filter kestrel-web build
make validate                                        # the whole gate, same as CI
make coverage                                        # HTML report in htmlcov/index.html
```

Tiers 2 and 3 need PostgreSQL at `DATABASE_URL` (host default `localhost:5433`,
matching the Compose published port; CI uses `localhost:5432`). Tier 1 never
connects. `examples/custom-connector` is discovered by the root run;
`examples/custom-connector/tests/conftest.py` puts the scaffold's `src/` on `sys.path` because it is
deliberately not a workspace member.

## Frontend

The web app's tests are [Vitest](https://vitest.dev/) unit tests over pure
logic: search-query parsing, graph layout and styling, widget queries, route
parameters, session-cookie and origin handling. They live next to the code as
`*.test.ts`, mostly under `apps/web/src/lib/`, and run in a Node environment
with no DOM (`apps/web/vitest.config.mts`).

```bash
pnpm --filter kestrel-web test       # same as test:unit
```

There are no component, browser, or end-to-end tests yet. Logic that can be
tested without rendering belongs in `src/lib/` so it gets a unit test; a
change to a page is checked with `pnpm --filter kestrel-web typecheck` and
`build`, and by hand against `make demo-up`.

## Isolation model

**Per-worker template databases.** Migrations are applied once into
`kestrel_test_template`. Each xdist worker then gets
`CREATE DATABASE kestrel_test_gw{n} TEMPLATE kestrel_test_template`; a serial run
uses `kestrel_test_main`. A worker owns its database outright, which is what
makes `-n auto` safe and a schema-resetting system test harmless.

- The template is reused between runs and rebuilt automatically when its `alembic_version` no longer matches head, so a new migration costs one rebuild.
- Worker databases are dropped at session end; `KESTREL_KEEP_TEST_DATABASES=1` keeps them for inspection.
- The harness refuses to create or drop any database not named `kestrel_test_*`, so the development database is out of reach.
- `KESTREL_TEST_DB_SLOT=<name>` namespaces the prefix, template, and advisory lock (`kestrel_test_<slot>_gw{n}`), for two pytest runs sharing one Postgres. Leave it unset for a single run and in CI.

**Savepoint-based rollback within a test.** `db_session` opens an outer
transaction and a SAVEPOINT, with an `after_transaction_end` listener that
restarts the savepoint whenever one ends. Application code calling
`session.commit()` only ever closes a savepoint; its effect is visible for the
rest of the test and the outer transaction rolls back at teardown. The engine is
session-scoped per worker.

**Tier 1 purity is enforced, not trusted.** `KESTREL_ASSERT_NO_DB=1` installs a
SQLAlchemy connect hook that fails any unit test opening a connection.

## Fixtures

| Fixture | Scope | What you get |
|---------|-------|--------------|
| `db_session` | function | A `Session` inside an outer transaction plus a restarting SAVEPOINT; nothing survives teardown |
| `db_engine` | session | The worker's `Engine`, built once |
| `test_database_url` | session | Provisions the worker database and points `DATABASE_URL` and the memoized engine at it; autouse in Tiers 2 and 3 |
| `worker_id` | session | `gw0`… under xdist, `main` serially |

## Environment the harness sets

Set in the root `conftest.py` before `kestrel` is imported:

| Variable | Value | Why |
|----------|-------|-----|
| `KESTREL_ENABLE_OBSERVABILITY` | `0` | No process-global tracer; no metrics port for workers to fight over |
| `KESTREL_POLICY_RUNTIME` | `restricted` | The measured 5.2x lever (133.4s → 25.5s on one file). Override to `subprocess` in tests that cover the isolation contract |
| `KESTREL_ARGON2_TIME_COST` / `_MEMORY_COST` / `_PARALLELISM` | `1` / `8` / `1` | 35ms → <0.1ms per hash; measured at only 1.7s of the old run, so not a headline lever |
| `KESTREL_RATE_LIMIT_ENABLED` | `0` | The fixed window is shared mutable state; a rate-limit test sets it back for itself |
| `KESTREL_RATE_LIMIT_BACKEND` | `memory` | A test that turns rate limiting back on counts in-process rather than against a developer's Redis |
| `KESTREL_MASTER_KEY` | random per worker | Tests never read the developer's `.env` |

All but observability use `setdefault`, so any can be overridden for a targeted
run. Opt-ins: `KESTREL_ASSERT_NO_DB=1`, `KESTREL_RUN_LIVE_TESTS=1`,
`KESTREL_KEEP_TEST_DATABASES=1`, `KESTREL_TEST_TEMPLATE_DB`, `KESTREL_TEST_DB_SLOT`.

## Shipped test helpers: `kestrel.testing`

`kestrel/src/kestrel/testing/` ships in the `kestrel` wheel, so a third-party
connector author gets the same helpers Kestrel's own suite uses. It imports no
`pytest` at module level.

| Helper | Use |
|--------|-----|
| `savepoint_session(engine)` | The context manager behind `db_session` |
| `RecordingTransport(responses, strict=True)` | Implements the connector SDK `Transport` protocol; serves canned bodies by path and records `request_calls` / `paginate_calls`; unknown paths raise `TransportPathNotFound` unless `strict=False` |
| `make_master_key()` | A valid base64 32-byte `KESTREL_MASTER_KEY`; `deterministic=True` for reproducible ciphertext |
| `make_organization` / `make_operator` / `make_application` / `make_application_instance` / `make_connector` / `make_connector_instance` | Row factories; each flushes, never commits, and generates unique names |
| `api_client(session, role)` | An authenticated `TestClient` on a fresh `create_app()`, so dependency overrides cannot leak; binds `session` as the request DB session; `task_queue=` captures enqueued work; exposes `.kestrel_org`, `.kestrel_operator`, `.kestrel_token` |
| `no_db_guard` | The `KESTREL_ASSERT_NO_DB` pytest plugin; downstream suites can use `-p kestrel.testing.no_db_guard` |

### Seams in application code these rely on

| Seam | Location | What it enables |
|------|----------|-----------------|
| `create_app()` | `apps/api/src/kestrel_api/main.py` | An isolated app per test instead of mutating the process-global `app`; `uvicorn kestrel_api.main:app` is unchanged |
| `get_engine()` / `get_sessionmaker()` / `reset_engine()` | `kestrel/src/kestrel/db/session.py` | Engine built on first use, so `DATABASE_URL` can be repointed after import |
| `get_task_queue` | `apps/api/src/kestrel_api/tasks_client.py` | One FastAPI dependency to override instead of monkeypatching every router that enqueues |
| Env-guarded worker imports | `apps/worker/src/kestrel_worker/celery_app.py` | Importing the worker does not bind a metrics port |
| `transport=` / `sleep=` | `kestrel/src/kestrel/connectors/sdk/transport.py` | Live pagination and 429-retry logic against `httpx.MockTransport` with injected sleep |
| `transport_override=` | `kestrel/src/kestrel/connectors/sdk/runner.py` | Fixture-first collection |
| `http_client=` | `kestrel/src/kestrel/webhooks/delivery.py`, `kestrel/src/kestrel/ticketing/protocol.py` | Injected HTTP clients |
| `KeyProvider` Protocol | `kestrel/src/kestrel/secrets/crypto.py` | Alternative key sources |
| `KESTREL_CELERY_TASK_ALWAYS_EAGER=1` | worker config | Runs Celery tasks inline; never set in production |

## Test module naming

Test directories contain **no `__init__.py`**. Under `--import-mode=importlib`
a module is named after its path relative to the repository root, which is
unique by construction. An `__init__.py` renames it after its package root, and
two same-basename files under truncated names collide silently: pytest runs one
file's body twice and never executes the other. Share helpers through
`kestrel.testing`, not through test-package imports. Three same-basename
`test_collection_identity.py` files, in `tests/unit/`, `tests/integration/`,
and `examples/custom-connector/tests/`, guard this.

## Speed

Costs measured against the old suite, ordered by how much they mattered:

| Cost | Measured | Fix |
|------|----------|-----|
| Every policy evaluation forks a fresh interpreter that imports the workspace | 537ms per spawn vs 20ms bare; 133.4s → 25.5s (5.2x) on one file | `KESTREL_POLICY_RUNTIME=restricted` for the bulk suite; a small dedicated set keeps the subprocess runtime covered |
| A full `run_sync` per test just to obtain rows to assert on | 22 of 43 integration files shared a ~6.3s floor | Factories; the pipeline is exercised where the pipeline is under test |
| Single-process execution | 468.6s wall, 98% in one tier | `pytest-xdist -n auto` over per-worker databases |
| `create_engine()` per test | small but pure waste | Session-scoped engine per worker |
| Argon2id at production parameters | 1.71s total across 49 call sites | Reduced parameters in tests; free, but not a headline lever |

## Coverage

Measured across the PR-gated suite (Tiers 1+2). `fail_under` in
`pyproject.toml` is a ratchet, not a target: raise it when coverage rises,
never lower it to make a build pass. Deleting the fully-unreachable
`investigate`, `inventory`, and `risks` packages moved it from the low 40s to
56%, which says something about what the old number was measuring. What is left
below the line is checkable: the routers (77%) and policy runtime are well
covered, while `gitops` and the CLI sit near zero. The CLI is the first
place worth raising the floor with.

## Review checklist

Reject a test that does any of the following:

- Runs `DROP SCHEMA` or destructive DDL against a shared database
- Writes anywhere inside the repository, especially `REPO_ROOT/.env`
- Asserts against process-global state (Prometheus registry, cached runtime singleton)
- Mutates `app.dependency_overrides` from a test body rather than a fixture
- Names a demo-fixture persona or hard-codes a path into `packs/` or `connectors/*/fixtures/`
- Calls `time.sleep`, compares against the wall clock, or makes a real network request
- Adds `skip` or `xfail` to make a run green

The anti-fragility property is verified, not asserted: break one policy
fixture and confirm that exactly one test fails.

## Expectations

- New behavior gets a test at the appropriate tier, marked by where it lives
- Do not skip failing tests to make CI green
- Do not claim validation ran unless command output exists
- Prefer fixture-based connector tests over live credentials
