#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# Cut a release.
#
#   scripts/release.sh 0.2.0            # prepare and tag, locally
#   scripts/release.sh 0.2.0 --push     # ...and push, which starts the release
#   scripts/release.sh 0.4.0 --prepared # tag an already-versioned release
#
# A release is a tag: pushing it re-runs CI, security, system and image checks,
# then creates the GitHub Release (.github/workflows/release.yaml). No
# container images are published; operators build them from deployments/docker/.
# This script exists so that
# the part a human does by hand is one command rather than four files and a
# changelog edit -- the four files are the version, and they have to agree or
# the tag stops meaning anything.
#
# It refuses to run anywhere that would produce a tag the release workflow
# will reject: the tag must be an ancestor of origin/main, and
# scripts/check-versions.sh must agree with it. Both are checked here first,
# where the fix costs nothing.
#
# See docs/operations/release-process.md.

set -euo pipefail

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*" >&2; }

VERSION="${1:-}"
PUSH=""
PREPARED=""
for option in "${@:2}"; do
  case "$option" in
    --push) PUSH=1 ;;
    --prepared) PREPARED=1 ;;
    *) die "unknown option: $option" ;;
  esac
done

[ -n "$VERSION" ] || die "usage: scripts/release.sh X.Y.Z [--prepared] [--push]"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]] \
  || die "'$VERSION' is not a semantic version. Pass 0.2.0, not v0.2.0."

TAG="v$VERSION"
cd "$(git rev-parse --show-toplevel)"

# --- refuse to build a release out of a tree nobody can reproduce -----------

[ -z "$(git status --porcelain)" ] || die "working tree is not clean."

branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = "main" ] || die "releases are cut from main; you are on '$branch'."

info "fetching origin/main"
git fetch --quiet --no-tags origin main
if ! git merge-base --is-ancestor origin/main HEAD; then
  die "main is behind origin/main. Pull first: a tag must be an ancestor of origin/main."
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "$TAG already exists locally."
fi
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  die "$TAG already exists on origin. Release tags are never overwritten, so cut the next patch version instead."
fi

current="$(sed -n 's/^version = "\(.*\)"/\1/p' kestrel/pyproject.toml | head -1)"
if [ -n "$PREPARED" ]; then
  [ "$current" = "$VERSION" ] || die "--prepared requires the tree to already say $VERSION."
  bash scripts/check-versions.sh "$VERSION"
  python3 - "$VERSION" <<'PY'
import datetime, re, sys
from pathlib import Path
version = sys.argv[1]
text = Path("CHANGELOG.md").read_text()
unreleased = re.search(r"^## Unreleased\s*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
if unreleased is None or unreleased[1].strip():
    sys.exit("error: --prepared needs an empty Unreleased section; include pending changes in the release notes first.")
section = re.search(rf"^## v{re.escape(version)} — (\d{{4}}-\d{{2}}-\d{{2}})\n(.*?)(?=^## |\Z)", text, re.M | re.S)
if section is None or not section[2].strip():
    sys.exit(f"error: --prepared needs non-empty, dated CHANGELOG notes for v{version}.")
datetime.date.fromisoformat(section[1])
PY
  uv sync --locked >/dev/null
else
  [ "$current" != "$VERSION" ] || die "the tree already says $VERSION. Use --prepared to tag the reviewed release."

# --- the version, everywhere it is recorded --------------------------------
#
# Keep this list and docs/operations/release-process.md in step with
# scripts/check-versions.sh, which is what actually enforces it.

info "$current -> $VERSION"

# From here on the tree is being rewritten. Anything that fails below -- a
# changelog with nothing in it, a version file that does not parse -- must not
# leave a half-bumped tree behind for someone to untangle by hand.
_restore() {
  local code=$?
  if [ "$code" -ne 0 ] && [ -z "${_committed:-}" ]; then
    git checkout --quiet -- . 2>/dev/null || true
    printf '\033[33mwarn:\033[0m reverted the version bump; the tree is as it was.\n' >&2
  fi
  exit "$code"
}
trap _restore EXIT

py_bump() {  # only [project].version, which is the first `version =` in the file
  python3 - "$1" "$VERSION" <<'PY'
import re, sys
path, new = sys.argv[1], sys.argv[2]
s = open(path).read()
s, n = re.subn(r'^version = "[^"]*"', f'version = "{new}"', s, count=1, flags=re.M)
assert n == 1, f"no [project] version in {path}"
open(path, "w").write(s)
PY
}
py_bump kestrel/pyproject.toml
py_bump apps/api/pyproject.toml
py_bump apps/worker/pyproject.toml

python3 - "$VERSION" <<'PY'
import json, re, sys
new = sys.argv[1]

p = "apps/web/package.json"
s = open(p).read()
s, n = re.subn(r'^(\s*"version":\s*")[^"]*(")', rf'\g<1>{new}\g<2>', s, count=1, flags=re.M)
assert n == 1, f"no version in {p}"
json.loads(s)
open(p, "w").write(s)
PY

# --- the changelog ---------------------------------------------------------
#
# Move whatever is under `## Unreleased` under a dated version heading and leave
# a fresh empty Unreleased behind. An empty Unreleased is a hard error: a
# release with no changelog entry is a release nobody can read.

python3 - "$VERSION" <<'PY'
import datetime, re, sys
new = sys.argv[1]
p = "CHANGELOG.md"
s = open(p).read()

m = re.search(r"^## Unreleased\s*\n", s, flags=re.M)
if not m:
    sys.exit("error: no '## Unreleased' heading in CHANGELOG.md")
start = m.end()
nxt = re.search(r"^## ", s[start:], flags=re.M)
end = start + nxt.start() if nxt else len(s)

body = s[start:end].strip()
if not body:
    sys.exit("error: '## Unreleased' is empty. A release needs a changelog entry.")

today = datetime.date.today().isoformat()
s = s[:m.start()] + f"## Unreleased\n\n## v{new} — {today}\n\n{body}\n\n" + s[end:]

# The standing "no tagged releases yet" note stops being true here.
s = s.replace(
    "This project has **no tagged releases yet**. The detailed development log from\n"
    "the initial build-out lives in",
    "The detailed development log from the initial build-out lives in")
open(p, "w").write(s)
print(f"CHANGELOG.md: moved Unreleased under v{new} — {today}")
PY

# --- the lockfile records those versions too -------------------------------
#
# uv.lock pins every workspace member, so bumping a pyproject without relocking
# leaves the two disagreeing. `uv sync --locked` then refuses -- which is every
# Python job in CI, and the Docker builds, and so the whole release. That is
# exactly how v0.1.1 failed.
#
# pnpm-lock.yaml does not record the importer's own version, so the web bump
# needs no equivalent. Check before adding one.

info "relocking uv.lock"
uv lock

# --- prove it, then tag ----------------------------------------------------

info "checking version consistency"
bash scripts/check-versions.sh "$VERSION"

# The assertion the bump exists to satisfy. CI runs `uv sync --locked` in six
# jobs and the Dockerfiles run `uv sync --frozen`; if the lockfile and the
# pyprojects disagree, all of it fails after the tag is already pushed. Prove it
# here, where the fix is free.
info "asserting the lockfile matches"
uv sync --locked >/dev/null

git add -A
git commit --quiet --signoff -m "Release $TAG"
_committed=1
fi

if git config --get user.signingkey >/dev/null 2>&1; then
  git tag -s "$TAG" -m "Kestrel $TAG"
else
  info "no signing key configured; creating an annotated tag"
  git tag -a "$TAG" -m "Kestrel $TAG"
fi

info "prepared $TAG"

if [ -n "$PUSH" ]; then
  # main first, always: the tag must be an ancestor of origin/main, and a tag
  # pushed before the commit it points at is not.
  info "pushing main, then $TAG"
  git push origin main
  git push origin "$TAG"
  echo
  echo "Released. Watch the release workflow:"
  echo "    gh run watch"
else
  echo
  echo "Nothing is pushed yet. Review with:"
  echo "    git show --stat HEAD"
  echo "Then:"
  echo "    git push origin main && git push origin $TAG"
fi
