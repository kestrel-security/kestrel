# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel connector create` must produce a connector whose own next steps work.

The CLI tells the author to run `kestrel connector validate <dir>` and
`uv run pytest <dir>/tests` before the connector is wired into the workspace.
Both have to pass on an untouched scaffold, with no credentials and no
`PYTHONPATH`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from kestrel.cli.connector import app
from typer.testing import CliRunner

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_scaffold_validates(tmp_path: Path) -> None:
    runner = CliRunner()
    created = runner.invoke(app, ["create", "my-app", "--dir", str(tmp_path)])
    assert created.exit_code == 0, created.output

    validated = runner.invoke(app, ["validate", str(tmp_path / "my-app")])
    assert validated.exit_code == 0, validated.output


def test_scaffold_tests_pass_before_wiring_in(tmp_path: Path) -> None:
    created = CliRunner().invoke(app, ["create", "my-app", "--dir", str(tmp_path)])
    assert created.exit_code == 0, created.output

    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(tmp_path / "my-app" / "tests"), "-q", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
