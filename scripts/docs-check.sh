#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/docs-check.sh — documentation gate.
#
#   1. Required documents exist.
#   2. Every relative Markdown link in every tracked .md file resolves, and a
#      link with a #fragment names a heading (or explicit anchor) that exists.
#   3. Every backtick-quoted repository path in Markdown (`docs/foo.md`,
#      `scripts/x.sh`) exists.
#   4. Every page under docs/ is listed in docs/README.md, and every ADR is
#      listed in docs/decisions.md.
#   5. No tracked non-Markdown file (code, CI, configuration) names a docs/*.md
#      path that does not exist -- a stale pointer, not a link, so check 2
#      cannot see it.
#   6. Every `make <target>` in Markdown code (inline or fenced) is a target
#      the Makefile defines.
#   7. Every KESTREL_* variable named in Markdown is documented in the root
#      .env.example (or, for Compose-only settings, deployments/compose/.env.example).
#
# Check 2 also covers HTML src/href/srcset attributes (<img src="...">) and
# links whose label itself contains brackets (badge links: [![alt](img)](url)).
#
# Paths listed in an optional .downstream-paths at the repository root are not
# checked (see docs/deployment.md, "Running from your own repository").
#
# Standard library only: the CI docs job runs it without uv.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REQUIRED=(
  README.md
  CONTRIBUTING.md
  SECURITY.md
  SUPPORT.md
  GOVERNANCE.md
  MAINTAINERS.md
  CODE_OF_CONDUCT.md
  CHANGELOG.md
  LICENSE
  NOTICE
  docs/README.md
  docs/getting-started.md
  docs/demo.md
  docs/architecture.md
  docs/threat-model.md
  docs/testing.md
  docs/connectors.md
  docs/connectors/authoring-tutorial.md
  docs/connectors/github-setup.md
  docs/connectors/google-workspace-setup.md
  docs/connectors/okta-setup.md
  docs/connectors/slack-setup.md
  docs/policies.md
  docs/findings.md
  docs/changes.md
  docs/identity-graph.md
  docs/dashboards.md
  docs/ticketing.md
  docs/gitops.md
  docs/domain-model.md
  docs/user-experience-principles.md
  docs/api.md
  docs/api-guidelines.md
  docs/deployment.md
  docs/observability.md
  docs/operations/scheduled-syncs.md
  docs/operations/rate-limiting.md
  docs/operations/data-retention.md
  docs/operations/release-process.md
  docs/product.md
  docs/roadmap.md
  docs/decisions.md
  docs/brand.md
  deployments/compose/docker-compose.yml
  deployments/compose/.env.example
  scripts/validate.sh
)

missing=0
for f in "${REQUIRED[@]}"; do
  if [[ ! -e "$f" ]]; then
    echo "MISSING: $f" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

python3 - <<'PY'
"""Links, anchors, quoted paths, index coverage and stale doc pointers."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(".").resolve()


def git_lines(*args: str) -> list[str]:
    out = subprocess.run(["git", *args], check=True, capture_output=True).stdout
    return [p.decode() for p in out.split(b"\0") if p]


tracked = set(git_lines("ls-files", "-z", "--cached", "--others", "--exclude-standard"))

# A repository that carries Kestrel alongside its own material lists that
# material in .downstream-paths; this gate describes Kestrel's tree, not theirs.
# One path per line, a trailing slash for a directory, # comments. Absent here.
downstream_file = ROOT / ".downstream-paths"
downstream = (
    [
        line.split("#", 1)[0].strip().rstrip("/")
        for line in downstream_file.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    if downstream_file.is_file()
    else []
)


def is_downstream(rel: str) -> bool:
    return any(rel == d or rel.startswith(d + "/") for d in downstream)


tracked_dirs = {str(Path(p).parents[i]) for p in tracked for i in range(len(Path(p).parents) - 1)}
top_level_dirs = {p.split("/", 1)[0] for p in tracked if "/" in p}
files = sorted(ROOT / p for p in tracked if p.endswith(".md") and not is_downstream(p) and (ROOT / p).is_file())

LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# A label with one level of brackets inside it: [![badge](img.svg)](target).
# LINK_RE finds the inner image; this finds the outer target.
NESTED_LINK_RE = re.compile(r"\[((?:[^\[\]]|\[[^\[\]]*\])*\[[^\[\]]*\](?:[^\[\]]|\[[^\[\]]*\])*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_ATTR_RE = re.compile(r"""<[a-zA-Z][^>]*?\s(src|href|srcset)\s*=\s*(["'])(.*?)\2""", re.S)
FENCE_RE = re.compile(r"^(```|~~~).*?^\1", re.M | re.S)
CODE_RE = re.compile(r"`([^`\n]+)`")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.M)
EXPLICIT_ANCHOR_RE = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"", re.I)
problems: list[str] = []


def strip_fences(text: str) -> str:
    return FENCE_RE.sub("", text)


def slugify(heading: str) -> str:
    """GitHub's heading anchor: rendered text, lowercased, punctuation dropped."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links -> their text
    text = re.sub(r"<[^>]+>", "", text)  # inline HTML
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchor_cache: dict[Path, set[str]] = {}


def anchors(path: Path) -> set[str]:
    if path not in _anchor_cache:
        text = path.read_text(encoding="utf-8")
        seen: dict[str, int] = {}
        found: set[str] = set(EXPLICIT_ANCHOR_RE.findall(text))
        for heading in HEADING_RE.findall(strip_fences(text)):
            slug = slugify(heading)
            n = seen.get(slug, 0)
            found.add(slug if n == 0 else f"{slug}-{n}")
            seen[slug] = n + 1
        _anchor_cache[path] = found
    return _anchor_cache[path]


def link_targets(text: str) -> list[str]:
    """Every relative-or-absolute target a Markdown file links to."""
    targets = [t for _label, t in LINK_RE.findall(text)]
    targets += [t for _label, t in NESTED_LINK_RE.findall(text)]
    for attr, _quote, value in HTML_ATTR_RE.findall(text):
        if attr == "srcset":
            # "a.png 1x, b.png 2x" -> each URL, descriptors dropped.
            targets += [c.strip().split()[0] for c in value.split(",") if c.strip()]
        else:
            targets.append(value)
    return targets


# --- 2. links and anchors -----------------------------------------------------
for path in files:
    rel = path.relative_to(ROOT)
    text = strip_fences(path.read_text(encoding="utf-8"))
    for target in link_targets(text):
        target = target.strip().strip("<>")
        if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target):
            continue
        file_part, _, fragment = target.partition("#")
        file_part = file_part.split("?", 1)[0]
        dest = (path.parent / file_part).resolve() if file_part else path
        try:
            dest.relative_to(ROOT)
        except ValueError:
            problems.append(f"{rel}: escapes repo -> {target}")
            continue
        if not dest.exists():
            problems.append(f"{rel}: broken link -> {target}")
            continue
        if fragment and dest.suffix == ".md" and fragment.lower() not in anchors(dest):
            problems.append(f"{rel}: no heading for anchor -> {target}")

# --- 3. backtick-quoted repository paths ---------------------------------------
PATH_RE = re.compile(r"^\.?[\w@-][\w.@-]*(/[\w.@-]+)+/?$")


def ignored(paths: list[str]) -> set[str]:
    if not paths:
        return set()
    out = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin", "-z"],
        input="\0".join(paths).encode(),
        capture_output=True,
    ).stdout
    return {p.decode() for p in out.split(b"\0") if p}


unresolved: list[tuple[Path, str, str]] = []
for path in files:
    text = strip_fences(path.read_text(encoding="utf-8"))
    for code in CODE_RE.findall(text):
        candidate = re.sub(r"(:\d+(-\d+)?|#[\w-]+)$", "", code.strip())
        if not PATH_RE.match(candidate) or candidate.split("/", 1)[0] not in top_level_dirs:
            continue
        clean = candidate.rstrip("/")
        if clean in tracked or clean in tracked_dirs:
            continue
        # Python-package shorthand: `kestrel/graph/writer.py` names
        # kestrel/src/kestrel/graph/writer.py.
        if f"kestrel/src/{clean}" in tracked or f"kestrel/src/{clean}" in tracked_dirs:
            continue
        # Placeholders in examples (`connectors/my-app/`).
        if re.search(r"(^|/)my[-_]", clean):
            continue
        # Also accept a path relative to the Markdown file itself.
        local = (path.parent / clean).resolve()
        if local.exists() and local.is_relative_to(ROOT):
            continue
        unresolved.append((path, code, clean))

# A path git ignores (deployments/compose/.env, a build output) is created
# locally by design and never tracked.
skip = ignored(sorted({c for _, _, c in unresolved}))
for path, code, clean in unresolved:
    if clean not in skip:
        problems.append(f"{path.relative_to(ROOT)}: quoted path does not exist -> `{code}`")

# --- 4. index coverage --------------------------------------------------------
# docs/README.md must link every page under docs/ except the ADRs (indexed by
# docs/decisions.md), the templates, and the history log.
index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
decisions = (ROOT / "docs" / "decisions.md").read_text(encoding="utf-8")
for path in files:
    rel = path.relative_to(ROOT)
    if rel.parts[0] != "docs" or rel.name == "README.md":
        continue
    inner = rel.relative_to("docs").as_posix()
    if inner.startswith("adr/"):
        if f"({inner})" not in decisions:
            problems.append(f"docs/decisions.md does not link {rel}")
        continue
    if inner.startswith("templates/") or inner.startswith("history/"):
        continue
    if f"({inner})" not in index:
        problems.append(f"docs/README.md does not link {rel}")

# --- 5. stale docs/*.md pointers outside Markdown -------------------------------
DOC_REF_RE = re.compile(r"(?<![\w/.-])docs/[\w./-]+?\.md\b")
for name in sorted(tracked):
    if name.endswith(".md") or name in {"scripts/docs-check.sh"} or is_downstream(name):
        continue
    p = ROOT / name
    if not p.is_file() or p.stat().st_size > 2_000_000:
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        for ref in DOC_REF_RE.findall(line):
            if ref not in tracked:
                problems.append(f"{name}:{lineno}: names a missing document -> {ref}")

# --- 6. make targets -------------------------------------------------------------
makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
make_targets = set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", makefile, re.M))
MAKE_RE = re.compile(r"(?<![\w./-])make\s+([a-z][\w-]*)")
for path in files:
    text = path.read_text(encoding="utf-8")
    code = [m.group(0) for m in FENCE_RE.finditer(text)] + CODE_RE.findall(strip_fences(text))
    for chunk in code:
        for target in MAKE_RE.findall(chunk):
            if target not in make_targets:
                problems.append(f"{path.relative_to(ROOT)}: `make {target}` is not a Makefile target")

# --- 7. KESTREL_* variables are documented ---------------------------------------
# A full name ends in a letter or digit, so prefixes written as `KESTREL_SMTP_*`
# are not taken for variables.
ENV_NAME_RE = re.compile(r"\bKESTREL_[A-Z0-9_]*[A-Z0-9]\b")
documented_env = set(ENV_NAME_RE.findall((ROOT / ".env.example").read_text(encoding="utf-8")))
documented_env |= set(ENV_NAME_RE.findall((ROOT / "deployments" / "compose" / ".env.example").read_text(encoding="utf-8")))
# Named in docs on purpose, deliberately not in .env.example.
ENV_ALLOWLIST = {
    # Test-harness switches, documented in docs/testing.md.
    "KESTREL_ASSERT_NO_DB",
    "KESTREL_KEEP_TEST_DATABASES",
    "KESTREL_RUN_LIVE_TESTS",
    "KESTREL_TEST_DB_SLOT",
    "KESTREL_TEST_TEMPLATE_DB",
    # A shell variable in curl examples, not configuration.
    "KESTREL_API",
}
for path in files:
    for name in sorted(set(ENV_NAME_RE.findall(path.read_text(encoding="utf-8")))):
        if name not in documented_env and name not in ENV_ALLOWLIST:
            problems.append(f"{path.relative_to(ROOT)}: {name} is not documented in .env.example")

if problems:
    print("Documentation problems:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    sys.exit(1)

print(f"docs-check OK ({len(files)} markdown files scanned)")
PY
