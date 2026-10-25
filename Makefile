# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
.PHONY: demo-verify sync dev down migrate revision test coverage lint format seed docs-check docs-serve docs-build check-versions hygiene api-docs demo demo-up demo-down demo-change db-reset validate release screenshots

sync:
	uv sync
	pnpm install

dev:
	docker compose up --build

down:
	docker compose down

migrate:
	uv run alembic upgrade head

revision:
	uv run alembic revision --autogenerate -m "$(m)"

test:
	uv run pytest -n auto

coverage:
	uv run pytest -m "unit or integration" -n auto --cov --cov-report=term:skip-covered --cov-report=html
	@echo "HTML report: htmlcov/index.html"

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy kestrel/src apps/api/src apps/worker/src connectors

format:
	uv run ruff format .
	uv run ruff check --fix .

# The whole demo environment in one command: Postgres + Redis, migrations,
# admin operator, four fixture tenants, the drift timeline, then the API,
# worker, and web containers, rebuilt from this checkout so a stale image from
# an older build is never what you look at. Sign in at http://localhost:3010.
demo-up:
	@bash scripts/demo-preflight.sh
	docker compose up -d postgres redis
	uv run kestrel demo up
	uv run kestrel demo change
	docker compose up -d --build api worker web
	@$(MAKE) --no-print-directory demo-verify
	@echo "Demo ready: http://localhost:3010/login  (admin@kestrel.local / kestrel-dev-password)"

# Tear the demo down: remove the demo tenants and everything derived from
# them (org, operators, policies, and packs stay), then stop the containers.
demo-down:
	uv run kestrel demo down --yes
	docker compose down

# Replay the drift timeline again on an existing demo (stacks onto the feed).
demo-change:
	uv run kestrel demo change

# Assert the demo estate still has every shape the walkthrough shows.
demo-verify:
	uv run kestrel demo verify

demo: demo-up

# Re-capture the README screenshots in docs/images/ from a running demo.
# ONLY=<file stem> captures one. See docs/images/README.md.
screenshots:
	ONLY=$(ONLY) node scripts/capture-screenshots.mjs

# Drop and recreate the local development database schema, then migrate.
# Destroys everything in it. Needed when the database was created by another
# branch or checkout and its migration revision is unknown here.
db-reset:
	@test "$(CONFIRM)" = "yes" || { echo "This destroys the local development database. Re-run as: make db-reset CONFIRM=yes"; exit 1; }
	docker compose up -d postgres
	docker compose exec -T postgres psql -U kestrel -d kestrel -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	uv run alembic upgrade head

seed:
	uv run kestrel init --seed --admin-email admin@kestrel.local --dev-password

docs-check:
	bash scripts/docs-check.sh

# The documentation site (mkdocs.yml). Links that leave docs/ point at main
# unless KESTREL_DOCS_REF names another ref.
docs-serve:
	uv run --only-group docs mkdocs serve

docs-build:
	uv run --only-group docs mkdocs build --strict

# Regenerate the route tables in docs/api.md from the OpenAPI schema.
api-docs:
	uv run python scripts/gen-api-docs.py

check-versions:
	bash scripts/check-versions.sh

# Secret scan + denylist of strings that must never appear in this repository.
hygiene:
	bash scripts/oss-hygiene.sh

validate:
	bash scripts/validate.sh

# Cut a release: bump the version everywhere it is recorded, move the CHANGELOG
# entries under a dated heading, and create the tag. Pushing the tag re-runs the
# CI/security/system/image gates and creates the GitHub Release; no images are published. See
# docs/operations/release-process.md.
#
#     make release VERSION=0.5.0          # prepare and tag, locally
#     make release VERSION=0.5.0 PUSH=1   # ...and push, which starts the release
#     make release VERSION=0.4.0 PREPARED=1 PUSH=1  # tag an already-prepared version
release:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=0.5.0 [PUSH=1]"; exit 1; }
	bash scripts/release.sh $(VERSION) $(if $(PREPARED),--prepared) $(if $(PUSH),--push)
