# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Every `KESTREL_*` variable the code reads is documented in `.env.example`.

The root `.env.example` is the reference for application configuration
(docs/deployment.md points at it). A variable added to the code without an
entry there is invisible to operators, which is how a dozen sync and policy
runtime settings went undocumented. This test scans the Python sources for
`KESTREL_*` names and fails on any the file does not mention.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Python source trees that ship: the core package, the apps, the connectors.
SOURCE_DIRS = (
    ROOT / "kestrel" / "src",
    ROOT / "apps" / "api" / "src",
    ROOT / "apps" / "worker" / "src",
    ROOT / "connectors",
)

# Read by the code, deliberately not operator configuration.
TEST_ONLY = frozenset(
    {
        # Turns the unit tier's no-database rule into a failure (kestrel.testing).
        "KESTREL_ASSERT_NO_DB",
    }
)

# A full name: ends in a letter or digit, so prefixes such as "KESTREL_LLM_"
# in prose are not mistaken for variables.
NAME_RE = re.compile(r"\bKESTREL_[A-Z0-9_]*[A-Z0-9]\b")


def _names_in_sources() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for base in SOURCE_DIRS:
        for path in sorted(base.rglob("*.py")):
            if "tests" in path.relative_to(base).parts:
                continue
            for name in NAME_RE.findall(path.read_text(encoding="utf-8")):
                found.setdefault(name, path)
    return found


def test_sources_mention_some_variables():
    # Guards the scan itself: an empty result would make the next test vacuous.
    assert "KESTREL_MASTER_KEY" in _names_in_sources()


def test_every_kestrel_variable_is_in_env_example():
    documented = set(NAME_RE.findall((ROOT / ".env.example").read_text(encoding="utf-8")))
    missing = {
        name: path.relative_to(ROOT).as_posix()
        for name, path in _names_in_sources().items()
        if name not in documented and name not in TEST_ONLY
    }
    assert not missing, (
        "KESTREL_* variables read by the code but absent from .env.example "
        f"(add a commented entry with its default): {missing}"
    )
