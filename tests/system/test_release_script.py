# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""First-release tagging against temporary Git repositories, never GitHub."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def release_checkout(tmp_path: Path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for name in ("kestrel", "apps/api", "apps/worker"):
        directory = checkout / name
        directory.mkdir(parents=True)
        (directory / "pyproject.toml").write_text('[project]\nversion = "0.4.0"\n')
    (checkout / "apps/web").mkdir()
    (checkout / "apps/web/package.json").write_text('{"version": "0.4.0"}\n')
    (checkout / "connectors").mkdir()
    (checkout / "connectors/.keep").touch()
    (checkout / "scripts").mkdir()
    for name in ("release.sh", "check-versions.sh"):
        shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
    (checkout / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n## v0.4.0 — 2026-10-10\n\nFirst release.\n")
    tools = tmp_path / "bin"
    tools.mkdir()
    uv = tools / "uv"
    # Exercise the Git/changelog/version transaction without installing a
    # workspace in every test. The real lockfile is checked by CI separately.
    uv.write_text("#!/bin/sh\nexit 0\n")
    uv.chmod(0o755)
    _git(checkout, "init", "-b", "main")
    _git(checkout, "config", "user.name", "Release Test")
    _git(checkout, "config", "user.email", "release@users.noreply.github.com")
    _git(checkout, "config", "commit.gpgsign", "false")
    _git(checkout, "add", ".")
    _git(checkout, "commit", "-s", "-m", "Prepare 0.4.0")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    _git(checkout, "remote", "add", "origin", str(remote))
    _git(checkout, "push", "origin", "main")
    return checkout, {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}


def _release(release_checkout, *args: str):
    root, environment = release_checkout
    return subprocess.run(["bash", "scripts/release.sh", *args], cwd=root, env=environment, text=True, capture_output=True)


def test_prepared_first_release_tags_without_a_version_bump(release_checkout) -> None:
    root, _environment = release_checkout
    before = _git(root, "rev-parse", "HEAD")
    result = _release(release_checkout, "0.4.0", "--prepared", "--push")
    assert result.returncode == 0, result.stderr
    assert _git(root, "rev-parse", "v0.4.0^{commit}") == before
    assert _git(root, "cat-file", "-t", "v0.4.0") == "tag"
    assert _git(root, "status", "--porcelain") == ""
    assert "refs/tags/v0.4.0" in _git(root, "ls-remote", "--tags", "origin")


@pytest.mark.parametrize("notes", ["## Unreleased\n\n## v0.4.0 — 2026-10-10\n", "## Unreleased\n\nUndocumented change.\n"])
def test_prepared_release_refuses_incomplete_notes(release_checkout, notes: str) -> None:
    root, _environment = release_checkout
    (root / "CHANGELOG.md").write_text(notes)
    _git(root, "add", ".")
    _git(root, "commit", "-s", "-m", "Change release notes")
    result = _release(release_checkout, "0.4.0", "--prepared")
    assert result.returncode != 0
    assert _git(root, "tag", "--list") == ""
    assert _git(root, "status", "--porcelain") == ""


def test_prepared_release_refuses_version_drift(release_checkout) -> None:
    root, _environment = release_checkout
    (root / "apps/web/package.json").write_text('{"version": "0.3.0"}\n')
    _git(root, "add", ".")
    _git(root, "commit", "-s", "-m", "Break version alignment")
    result = _release(release_checkout, "0.4.0", "--prepared")
    assert result.returncode != 0
    assert "Version consistency check failed" in result.stderr
    assert _git(root, "tag", "--list") == ""
