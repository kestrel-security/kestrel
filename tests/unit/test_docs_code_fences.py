# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Every ```yaml and ```python fence in the docs must parse.

Readers copy these blocks into manifests and connector code. A block whose
indentation has collapsed renders without complaint but is invalid when
pasted. This lives here rather than in scripts/docs-check.sh because that
script is standard-library only and cannot parse YAML.
"""

from __future__ import annotations

import ast
import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
# The opening fence may be indented inside a list item; the body keeps that indent.
_FENCE = re.compile(r"^(?P<indent>[ ]*)```(?P<lang>yaml|yml|python)[ ]*\n(?P<body>.*?)^(?P=indent)```", re.M | re.S)


def _markdown_files() -> list[Path]:
    tracked = subprocess.run(
        ["git", "ls-files", "README.md", "docs/*.md", "docs/**/*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return sorted({REPO_ROOT / path for path in tracked})


def _fence_errors(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = []
    for fence in _FENCE.finditer(text):
        body = textwrap.dedent(fence["body"])
        line = text.count("\n", 0, fence.start()) + 1
        try:
            if fence["lang"] == "python":
                ast.parse(body)
            else:
                yaml.safe_load(body)
        except (SyntaxError, yaml.YAMLError) as exc:
            summary = str(exc).splitlines()[0]
            errors.append(f"{path.relative_to(REPO_ROOT)}:{line}: {fence['lang']} fence does not parse: {summary}")
    return errors


@pytest.mark.parametrize("path", _markdown_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_code_fences_parse(path: Path) -> None:
    errors = _fence_errors(path)
    assert not errors, "\n".join(errors)
