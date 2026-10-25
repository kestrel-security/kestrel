#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/validate.sh — repository validation gate: the same checks CI runs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_TESTS=0
SKIP_WEB=0
DOCS_ONLY=0

usage() {
  cat <<'EOF'
Usage: scripts/validate.sh [--docs-only] [--skip-tests] [--skip-web]

Runs documentation and hygiene checks, Python lint/format/typecheck, tests, and optional web lint/typecheck/build.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docs-only) DOCS_ONLY=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --skip-web) SKIP_WEB=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

echo "==> docs check"
bash "$ROOT/scripts/docs-check.sh"

echo "==> version consistency"
bash "$ROOT/scripts/check-versions.sh"

echo "==> repository hygiene"
bash "$ROOT/scripts/oss-hygiene.sh"

if [[ "$DOCS_ONLY" -eq 1 ]]; then
  echo "OK (docs-only)"
  exit 0
fi

echo "==> ruff"
uv run ruff check .
uv run ruff format --check .

echo "==> mypy"
uv run mypy kestrel/src apps/api/src apps/worker/src connectors

# Same Tier 0 checks the `static` job in .github/workflows/ci.yaml runs. Kept in
# step with it deliberately: when the local gate and the remote gate drift, the
# local one stops being worth running.
echo "==> alembic SQL dry-run"
uv run alembic upgrade head --sql >/dev/null

echo "==> api docs freshness"
uv run python "$ROOT/scripts/gen-api-docs.py" --check

echo "==> connector manifests"
for dir in "$ROOT"/connectors/*/; do
  uv run kestrel connector validate "$dir" >/dev/null
done

if [[ "$SKIP_TESTS" -eq 0 ]]; then
  # Tiers 1-3. CI splits these across jobs and leaves Tier 3 to nightly.yaml;
  # locally there is no reason not to run everything.
  echo "==> pytest (all tiers)"
  uv run pytest -n auto -q
else
  echo "==> pytest skipped"
fi

if [[ "$SKIP_WEB" -eq 0 ]]; then
  if [[ -d "$ROOT/apps/web/node_modules" ]] || [[ -d "$ROOT/node_modules" ]]; then
    echo "==> web lint"
    pnpm --filter kestrel-web lint
    echo "==> web typecheck"
    pnpm --filter kestrel-web typecheck
    echo "==> web tests"
    pnpm --filter kestrel-web test:unit
    echo "==> web build"
    pnpm --filter kestrel-web build
  else
    echo "==> FAIL: node_modules missing -- run 'pnpm install' (CI has no such" >&2
    echo "    leniency, so skipping here would make a local pass meaningless)" >&2
    exit 1
  fi
else
  echo "==> web checks skipped"
fi

echo "OK"
