#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/ci-changes.sh — classify a pull request as docs-only or not.
#
# Usage: ci-changes.sh BASE_SHA HEAD_SHA
#
# Prints `docs_only=true` or `docs_only=false`, and appends the same line to
# $GITHUB_OUTPUT when it is set. ci.yaml and security-scan.yaml skip their
# heavy jobs (database tiers, web build, dependency audits) when it is true.
#
# Docs-only means every file the pull request adds, changes, or deletes is
# Markdown or an image under docs/images/, with these exceptions, which are
# read by checks that docs-only pull requests skip:
#
#   docs/api.md ...... generated from the OpenAPI schema; Tier 0 checks it.
#
# Markdown that Tier 1 tests parse (README.md, docs/**, posture baselines)
# stays on the allow-list because Tier 1 always runs. Add a path to EXCEPTIONS
# when a skipped job starts reading it.
#
# Anything uncertain answers false: no arguments, an unreadable range, or an
# empty diff all run the full gate.
set -uo pipefail

EXCEPTIONS=(
  "docs/api.md"
)

emit() {
  echo "docs_only=$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "docs_only=$1" >>"$GITHUB_OUTPUT"
  fi
  exit 0
}

base="${1:-}"
head="${2:-}"
[[ -n "$base" && -n "$head" ]] || emit false

# Three dots: what the pull request changed since it branched, not what main
# changed since. --no-renames lists both sides of a rename.
if ! files="$(git diff --name-only --no-renames "${base}...${head}")"; then
  emit false
fi
[[ -n "$files" ]] || emit false

while IFS= read -r path; do
  for exception in "${EXCEPTIONS[@]}"; do
    [[ "$path" == "$exception" ]] && emit false
  done
  case "$path" in
    *.md) ;;
    docs/images/*.png | docs/images/*.svg | docs/images/*.jpg | docs/images/*.gif | docs/images/*.webp) ;;
    *) emit false ;;
  esac
done <<<"$files"

emit true
