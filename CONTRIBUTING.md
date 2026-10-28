# Contributing to Kestrel

Thanks for your interest in Kestrel. This guide covers setup, conventions, and how to get a change merged. It assumes you have never seen the repository before.

## Before you start

- **Questions:** ask in [GitHub Discussions](https://github.com/kestrel-security/kestrel/discussions); see [`SUPPORT.md`](SUPPORT.md).
- **Bugs and features:** open an issue using the templates. Comment on the issue so nobody duplicates the work.
- **Security vulnerabilities:** do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).
- **Larger changes** (new connector, schema change, anything architectural): open an issue first describing the approach. Architecturally significant decisions get an ADR under `docs/adr/` and an entry in `docs/decisions.md`.

### Your first contribution

Issues labelled [`good first issue`](https://github.com/kestrel-security/kestrel/labels/good%20first%20issue) (when there are any) are scoped to be finishable without knowing the whole codebase, and say where to start. Connectors, policies, and documentation fixes are good places to begin otherwise; [`docs/roadmap.md`](docs/roadmap.md) lists open work. Comment on an issue to claim it, ask questions on the issue, and open a draft pull request early: a half-finished change with a question is easier to help with than a finished one that went the wrong way.

### How a change gets in

Anyone can contribute; you do not need write access to the repository. The process is the standard GitHub fork-and-pull-request flow:

1. **Fork** `kestrel-security/kestrel` on GitHub and clone your fork ([Setting up](#setting-up)).
2. **Branch** from the current `main`, make the change, and sign off every commit ([Making a change](#making-a-change)).
3. **Push** the branch to your fork and **open a pull request** against `main` in the upstream repository ([Pull requests](#pull-requests)).
4. **CI runs** (a maintainer approves the first run on pull requests from outside the project) and a **maintainer reviews**. Address feedback by pushing more commits to the same branch.
5. A maintainer **squash-merges** the pull request once a code-owner approval and every required check are in place. Only maintainers can merge; there is no self-merge.

Maintainers listed in [`MAINTAINERS.md`](MAINTAINERS.md) work on branches in the main repository and follow the same review rules. Nobody else can push to it, so a fork is the only route in.

## Required tooling

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.12+ | `.python-version` |
| [`uv`](https://docs.astral.sh/uv/) | current | Python workspace and lockfile |
| Node.js | 22+ | `.nvmrc` |
| `pnpm` | 10.x | `packageManager` in `package.json` (`corepack enable` installs it, or [install pnpm directly](https://pnpm.io/installation) on a Node build without corepack) |
| Docker with Compose | current | PostgreSQL 16 and Redis 7 |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | optional | `make hygiene` uses it when present; CI always runs it |

## Setting up

Fork the repository on GitHub first (the **Fork** button on [kestrel-security/kestrel](https://github.com/kestrel-security/kestrel)), then clone your fork and add the upstream repository as a second remote so you can keep `main` current:

```bash
git clone git@github.com:YOUR-USERNAME/kestrel.git && cd kestrel
git remote add upstream https://github.com/kestrel-security/kestrel.git
git fetch upstream
make sync                        # uv sync && pnpm install
docker compose up -d postgres redis
uv run kestrel demo up           # migrations, .env, admin operator, fixture tenants
```

Then either run the full container stack (`make dev`) or run the services on the host with live reload. Host processes do not read `.env`, so give the API and worker the master key `kestrel demo up` generated (without it, saving any connector, webhook, SMTP, or MFA secret fails):

```bash
export KESTREL_MASTER_KEY="$(grep '^KESTREL_MASTER_KEY=' .env | cut -d= -f2-)"
uv run uvicorn kestrel_api.main:app --reload --port 8010
uv run celery -A kestrel_worker.celery_app worker --beat -l info
API_URL=http://localhost:8010/api/v1 pnpm --filter kestrel-web dev
```

Sign in with `admin@kestrel.local` / `kestrel-dev-password` at `http://localhost:3000` when the web app runs on the host (`pnpm --filter kestrel-web dev`), or `http://localhost:3010` with the container stack (`make dev`).

Host-side tools (CLI, Alembic, pytest) reach Compose on the **published** ports: PostgreSQL `localhost:5433`, Redis `localhost:6380`. The `.env` file uses Docker service names for containers; do not export it into your shell. Details and troubleshooting: [`docs/getting-started.md`](docs/getting-started.md).

## Where things live

| Path | What |
|------|------|
| `kestrel/` | Core library: models, connector SDK, sync, graph, changes, policies, findings, secrets, CLI. No dependency on the apps. |
| `apps/api/` | FastAPI service. Routers under `src/kestrel_api/routers/`. |
| `apps/worker/` | Celery tasks for sync, policy evaluation, webhooks, schedules. |
| `apps/web/` | Next.js UI. Pages under `src/app`, components under `src/components`, API access and tested logic under `src/lib`. |
| `connectors/` | One installable package per application, built on `kestrel.connectors.sdk`. |
| `packs/` | First-party policy packs: Python policies, fixtures, compliance mappings. |
| `migrations/` | Alembic. |
| `tests/` | Tiered suite: `unit/` (no DB), `integration/` (PostgreSQL), `system/` (CLI end-to-end). |
| `docs/` | Domain docs, ADRs, connector guides, operations, product briefs. |

Orientation: [`docs/architecture.md`](docs/architecture.md).

## Making a change

1. Start from the current upstream `main` and branch from it:

   ```bash
   git fetch upstream
   git checkout -b my-change upstream/main
   ```

2. Keep the change focused. One coherent task per pull request.
3. Add or update tests at the right tier (see below).
4. Run the checks for what you touched, then `make validate` before opening the PR.
5. Update docs that describe the behavior you changed, and add a line under **Unreleased** in `CHANGELOG.md` when the change is user-facing.
6. Push the branch to your fork (`git push -u origin my-change`) and open the pull request from there. If `main` moves while your PR is open, rebase onto `upstream/main` rather than merging it in; required checks run against the merged result, so an out-of-date branch is re-tested anyway.

### Checks

```bash
uv run ruff check . && uv run ruff format --check .   # lint + format (make format fixes both)
uv run mypy kestrel/src apps/api/src apps/worker/src connectors   # types (or just: make lint)
uv run pytest -m unit -q                               # Tier 1, no database
uv run pytest -m "unit or integration" -n auto -q      # the PR gate
pnpm --filter kestrel-web lint && pnpm --filter kestrel-web typecheck && pnpm --filter kestrel-web test:unit && pnpm --filter kestrel-web build
make hygiene                                           # secret scan + forbidden-string check
make validate                                          # everything CI runs, in one command
```

CI runs the same gate on every pull request (`.github/workflows/ci.yaml`, `security-scan.yaml`, `commits.yaml`).

Optionally, `uvx pre-commit install` runs ruff, the web lint, a secret scan,
and whitespace checks on each commit (`.pre-commit-config.yaml`). They mirror
CI, so skipping them only means finding a problem later.

### Testing expectations

The full guide is [`docs/testing.md`](docs/testing.md). In short:

- **Tier 1 (`tests/unit/`, with connector tests in `tests/unit/connectors/`)** — pure logic, no database, no network, no subprocess. `KESTREL_ASSERT_NO_DB=1` makes a violation fail.
- **Tier 2 (`tests/integration/`)** — real PostgreSQL session, API via `TestClient`, connectors via fixture transports.
- **Tier 3 (`tests/system/`)** — CLI end-to-end and migration replay; runs nightly.
- Tests create their own data through the factories in `kestrel.testing`. Never assert on a demo persona or a hard-coded path under `packs/`.
- Nothing writes inside the repository during a test; write to `tmp_path`.
- Test directories have no `__init__.py`. The one exception is a scaffolded connector package (`kestrel connector create` writes an `__init__.py` into its tests directory): it is a standalone package run with its own `pytest` invocation, not collected by the repository's root run.
- **Frontend:** Vitest unit tests for pure logic, next to the code as `*.test.ts` (mostly `apps/web/src/lib/`); run `pnpm --filter kestrel-web test`. There are no component or browser tests yet.

### Code conventions

- **Python:** SQLAlchemy 2.0 typed `Mapped` / `mapped_column`; Pydantic for external schemas; `typing.Protocol` for SDK contracts. Library code raises typed errors and uses `logging`; the CLI uses `typer.echo`. No `print()` in `kestrel/src`. Every query is scoped by `org_id`.
- **TypeScript:** prefer Server Components and Server Actions; keep API access in `apps/web/src/lib`.
- **Comments** explain *why*, not *what*. Delete commented-out code instead of keeping it.
- **No speculative abstractions.** Three similar lines beat a premature framework.
- **Honest labels.** Docs and docstrings say implemented, partial, or proposed. Unfinished work gets a GitHub issue, not a vague comment.
- **Public-repository hygiene.** No secrets, personal identifiers, or private hostnames. `make hygiene` runs the denylist and a secret scan.

### Commit messages and sign-off

Kestrel uses the [Developer Certificate of Origin](https://developercertificate.org/) 1.1 ([DEC-010](docs/decisions.md); `DEC-nnn` references throughout the docs point into that decision log). Every commit must carry a sign-off line certifying that you wrote the change or have the right to submit it under Apache License 2.0:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it from your git `user.name` / `user.email`. There is no CLA.

The **DCO check** (`.github/workflows/commits.yaml`) runs on every pull request and fails when a commit (merge commits aside) lacks a `Signed-off-by:` trailer whose email matches that commit's author email. To sign off commits you already made:

```bash
git fetch upstream
git rebase --signoff upstream/main
git push --force-with-lease
```

Write commit messages as a short imperative summary line, optionally followed by a paragraph explaining why. Reference the issue when there is one.

## Pull requests

- Open the PR from your fork against `main` in `kestrel-security/kestrel`, using the template. Fill in the test plan with what you actually ran. Mark it as a draft if it is not ready for review.
- Keep PRs reviewable: if a refactor is needed to make a change, land the refactor first.
- **CI on pull requests from forks waits for a maintainer to approve the run.** This is a GitHub Actions safeguard for public repositories, not a judgement on the change; checks will show as pending until a maintainer clicks *Approve and run*. CI secrets are never available to fork pull requests, and nothing in the required checks needs them.
- CI must be green. Do not skip or weaken a check to get there; ask in the PR if a check looks wrong.
- Pull requests that only change Markdown (or images under `docs/images/`) run a shorter CI gate that skips the database tiers, web build, and dependency audits; those checks show as skipped, which counts as passing. Keep documentation fixes in their own pull request to get the faster gate. Details: [`docs/testing.md`](docs/testing.md#tiers).
- Merging requires one approving review from a code owner ([`.github/CODEOWNERS`](.github/CODEOWNERS)) and every required check passing. Pull requests are squash-merged, so a tidy PR title and description become the commit on `main`; the individual commits do not need to be polished, but each must be signed off.
- Be responsive to review. Maintainers aim to respond within a few days. Significant changes stay open for at least three working days so other maintainers can object ([`GOVERNANCE.md`](GOVERNANCE.md)).

## Adding a connector

```bash
uv run kestrel connector create my-app        # working, fixture-backed template
uv run kestrel connector validate connectors/my-app
uv run pytest connectors/my-app/tests -q
```

1. Build fixture-first; validate offline before touching live credentials.
2. Declare read-only scopes in `manifest.yaml`. The loader rejects write scopes.
3. Normalize into the kinds the change-detection pipeline already diffs (`identity`, `grant`, `group_membership`, `oauth_*`, `setting`) so **Changes** works without connector-specific code.
4. Add the package to `[tool.uv.workspace].members` in `pyproject.toml` and to the connector entry points, then include a README that says what is collected and what is not.
5. Move its unit tests to `tests/unit/connectors/` (the default `pytest` run does not collect `connectors/*/tests/`); the shared fixture contract test picks the connector up automatically.

Guides: [`docs/connectors/authoring-tutorial.md`](docs/connectors/authoring-tutorial.md), [`docs/connectors.md`](docs/connectors.md), [`examples/custom-connector/`](examples/custom-connector/).

## Adding a policy

1. Write `policy(resource) -> bool` in a `.py` module with a JSON fixtures file beside it.
2. `uv run kestrel policy validate path/to/policy.py` and `uv run kestrel policy test path/to/policy.py --fixtures path/to/fixtures.json`.
3. Ship it in a pack (`pack.yaml`) with a compliance mapping when one applies.

Guide: [`docs/policies.md`](docs/policies.md), ADR-0009.

## Changing the schema

1. Edit the SQLAlchemy models.
2. `make revision m="describe the change"` and review the generated migration by hand.
3. `make migrate`, then run the integration tier.
4. Prefer additive migrations. Irreversible migrations need explicit maintainer approval.

## Documentation

- Update the page that describes what you changed; every page is listed in [`docs/README.md`](docs/README.md), and a new page must be added there (`make docs-check` fails otherwise).
- Routes: after adding or changing an endpoint, run `make api-docs`; `tests/unit/test_api_docs.py` fails when `docs/api.md` is stale or names a route that does not exist.
- Keep relative links working; `make docs-check` verifies every tracked Markdown file.
- One page per surface, no per-task briefs. Ship-notes go in `CHANGELOG.md`; open work in GitHub issues; decisions in `docs/decisions.md` or an ADR.

## Code of conduct and governance

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). How decisions are made and who makes them: [`GOVERNANCE.md`](GOVERNANCE.md) and [`MAINTAINERS.md`](MAINTAINERS.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the rest of the repository.
