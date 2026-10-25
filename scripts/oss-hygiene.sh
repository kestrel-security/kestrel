#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/oss-hygiene.sh — fail when the repository contains things that must
# never appear in it.
#
# Checks:
#   tree     The Apache-2.0 header on every source file (license-headers.py).
#            A denylist of patterns (below) over tracked and untracked (not
#            ignored) files, via `git grep`, so it needs no extra tooling and
#            never wanders into node_modules or .venv. Then gitleaks over the
#            working tree, when gitleaks is installed (CI runs it separately in
#            security-scan.yaml, so its absence locally is a warning).
#   commits  The same patterns over commit metadata -- author and committer
#            names and emails, and messages -- plus an allow-list for author and
#            committer emails (GitHub noreply addresses). Maintainer-only: CI
#            runs it on same-repository branches, never on forks, so outside
#            contributors may commit with any address.
#
# Usage:
#   scripts/oss-hygiene.sh                   # tree only (what contributors run)
#   scripts/oss-hygiene.sh --tree            # the same, explicitly (the CI docs job)
#   scripts/oss-hygiene.sh --commits [RANGE] # commits only; RANGE defaults to HEAD
#                                            # (e.g. origin/main..HEAD)
#
# Extra patterns: maintainers can add private patterns (one extended regex per
# line, '#' comments allowed) without publishing them, in a gitignored
# .hygiene-denylist.local at the repository root and/or the
# HYGIENE_EXTRA_PATTERNS environment variable (newline-separated; CI sets it
# from a repository secret of the same name).
#
# Downstream paths: a repository that carries Kestrel alongside its own
# material (deployment config, private runbooks) lists that material in a
# .downstream-paths file at the root -- one path per line, a trailing slash for
# a directory, '#' comments -- and the tree denylist skips it. Kestrel itself has
# no such file. gitleaks still scans everything.
#
# Exit non-zero on any hit. Add an exclusion only with a written reason.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Case-insensitive POSIX extended regexes: personal mailboxes and links into
# private chat and trackers. (A maintainer's GitHub handle is public and is
# part of every noreply address, so it is allowed.) Keep each one narrow
# enough that legitimate technical uses do not match.
PATTERNS=(
  '@gmail\.com'
  'slack\.com/archives'
  'atlassian\.net/browse'
)

# Private extra patterns (see the header). Blank lines and comments are skipped.
load_extra_patterns() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] && PATTERNS+=("$line")
  done
}
if [[ -f .hygiene-denylist.local ]]; then
  load_extra_patterns < .hygiene-denylist.local
fi
if [[ -n "${HYGIENE_EXTRA_PATTERNS:-}" ]]; then
  load_extra_patterns <<<"$HYGIENE_EXTRA_PATTERNS"
fi

# Case-sensitive: local home-directory paths. Case matters because API paths
# such as Okta's `/api/v1/users/{id}` are legitimate.
CASE_PATTERNS=(
  '/Users/'
  '/home/[a-z]'
)

# Author and committer emails allowed in commit metadata (extended regex,
# case-insensitive). Override with HYGIENE_EMAIL_ALLOW.
EMAIL_ALLOW="${HYGIENE_EMAIL_ALLOW:-(@users\.noreply\.github\.com|^noreply@github\.com)$}"

# Files the denylist does not apply to: lockfiles, binary assets, and this
# script itself (which lists the patterns).
PATHSPECS=(
  ':(glob)**'
  ':(exclude)uv.lock'
  ':(exclude)pnpm-lock.yaml'
  ':(exclude,glob)**/*.png'
  ':(exclude,glob)**/*.jpg'
  ':(exclude,glob)**/*.pdf'
  ':(exclude,glob)**/*.ico'
  ':(exclude,glob)**/*.tgz'
  ':(exclude)scripts/oss-hygiene.sh'
)
if [[ -f .downstream-paths ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] && PATHSPECS+=(":(exclude)${line%/}")
  done < .downstream-paths
fi

status=0

check_tree() {
  local pattern hits
  for pattern in "${PATTERNS[@]}"; do
    if hits="$(git grep -n -i -E --untracked -e "$pattern" -- "${PATHSPECS[@]}" 2>/dev/null)"; then
      echo "oss-hygiene: forbidden pattern '${pattern}':" >&2
      echo "$hits" >&2
      status=1
    fi
  done
  for pattern in "${CASE_PATTERNS[@]}"; do
    if hits="$(git grep -n -E --untracked -e "$pattern" -- "${PATHSPECS[@]}" 2>/dev/null)"; then
      echo "oss-hygiene: forbidden pattern '${pattern}':" >&2
      echo "$hits" >&2
      status=1
    fi
  done

  # Every source file carries the Apache-2.0 header.
  if ! python3 scripts/license-headers.py --check >/dev/null; then
    status=1
  fi

  if command -v gitleaks >/dev/null 2>&1; then
    # A working tree legitimately holds a gitignored .env with a real master
    # key. Exempt it for this scan only, never in .gitleaks.toml, which
    # `gitleaks git` in CI also reads.
    local config
    config="$(mktemp)"
    {
      printf '[extend]\npath = "%s/.gitleaks.toml"\n\n' "$ROOT"
      printf "[allowlist]\npaths = ['''(^|/)\\\\.env\$''', '''(^|/)\\\\.env\\\\.local\$''']\n"
    } >"$config"
    if ! gitleaks dir --no-banner --redact --exit-code 1 --config "$config" . >/dev/null 2>&1; then
      echo "oss-hygiene: gitleaks found a possible secret (run: gitleaks dir --redact --config .gitleaks.toml .)" >&2
      status=1
    fi
    rm -f "$config"
  else
    echo "oss-hygiene: gitleaks not installed; skipping secret scan (CI runs it)" >&2
  fi
}

check_commits() {
  local range="$1" sha meta email pattern bad=0
  if ! git rev-parse --verify --quiet "${range##*..}^{commit}" >/dev/null; then
    echo "oss-hygiene: cannot resolve commit range '${range}'" >&2
    status=1
    return
  fi
  for sha in $(git rev-list "$range"); do
    # The same shape as `git log --format='%an %ae %cn %ce %B'`, one commit at a time.
    meta="$(git show -s --format='%an %ae %cn %ce %B' "$sha")"
    for pattern in "${PATTERNS[@]}"; do
      if grep -qiE -e "$pattern" <<<"$meta"; then
        echo "oss-hygiene: commit $(git show -s --format='%h %s' "$sha"): forbidden pattern '${pattern}'" >&2
        bad=1
      fi
    done
    for pattern in "${CASE_PATTERNS[@]}"; do
      if grep -qE -e "$pattern" <<<"$meta"; then
        echo "oss-hygiene: commit $(git show -s --format='%h %s' "$sha"): forbidden pattern '${pattern}'" >&2
        bad=1
      fi
    done
    for email in $(git show -s --format='%ae %ce' "$sha"); do
      if ! grep -qiE -e "$EMAIL_ALLOW" <<<"$email"; then
        echo "oss-hygiene: commit $(git show -s --format='%h %s' "$sha"): email '${email}' is not on the allow-list" >&2
        bad=1
      fi
    done
  done
  if [[ "$bad" -ne 0 ]]; then
    echo "oss-hygiene: use a GitHub noreply address (https://github.com/settings/emails)" >&2
    status=1
  fi
}

case "${1:-}" in
  ""|--tree)
    check_tree
    ;;
  --commits)
    check_commits "${2:-HEAD}"
    ;;
  *)
    echo "usage: $0 [--tree | --commits [RANGE]]" >&2
    exit 2
    ;;
esac

if [[ "$status" -ne 0 ]]; then
  echo "oss-hygiene: FAILED" >&2
  exit "$status"
fi
echo "oss-hygiene OK"
