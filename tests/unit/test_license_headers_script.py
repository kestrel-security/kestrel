# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""scripts/license-headers.py against temporary Git repositories."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    shutil.copyfile(ROOT / "scripts" / "license-headers.py", tmp_path / "scripts" / "license-headers.py")
    (tmp_path / "app.py").write_text('"""An app module."""\n')
    (tmp_path / "run.sh").write_text("#!/usr/bin/env bash\necho hi\n")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "deploy.sh").write_text("#!/usr/bin/env bash\necho deploy\n")
    (tmp_path / "AGENTS.md").write_text("notes\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return subprocess.run([sys.executable, "scripts/license-headers.py", *args], cwd=root, text=True, capture_output=True)


def test_adds_the_header_after_a_shebang_and_is_idempotent(checkout: Path) -> None:
    assert _run(checkout).returncode == 0
    assert (checkout / "run.sh").read_text().splitlines()[:3] == [
        "#!/usr/bin/env bash",
        "# Copyright 2026 The Kestrel Authors",
        "# SPDX-License-Identifier: Apache-2.0",
    ]
    once = (checkout / "app.py").read_text()
    assert _run(checkout).returncode == 0
    assert (checkout / "app.py").read_text() == once
    assert _run(checkout, "--check").returncode == 0


def test_check_fails_and_names_the_file_missing_a_header(checkout: Path) -> None:
    result = _run(checkout, "--check")
    assert result.returncode == 1
    assert "app.py" in result.stderr
    assert "SPDX" not in (checkout / "app.py").read_text()


def test_skips_the_paths_a_downstream_repository_owns(checkout: Path) -> None:
    (checkout / ".downstream-paths").write_text("# Private material.\ninfra/\n")
    assert _run(checkout).returncode == 0
    assert "SPDX" not in (checkout / "infra" / "deploy.sh").read_text()
    assert "SPDX" in (checkout / "app.py").read_text()
    assert _run(checkout, "--check").returncode == 0
