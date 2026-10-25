# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""``kestrel init`` / ``kestrel demo up`` explain an unknown migration revision.

A database created by another branch reports ``Can't locate revision`` from
Alembic. That must surface as an actionable message with the reset command,
not a stack trace; any other Alembic failure still propagates.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from alembic.util.exc import CommandError
from kestrel.cli import init as init_cli


def _repo_root_with_alembic_ini(tmp_path: Path) -> Path:
    (tmp_path / "alembic.ini").write_text("[alembic]\nscript_location = migrations\n")
    return tmp_path


def test_unknown_revision_becomes_actionable_exit(monkeypatch, tmp_path, capsys) -> None:
    def boom(cfg, revision):
        raise CommandError("Can't locate revision identified by 'd2e3f4a5b6c7'")

    monkeypatch.setattr(init_cli.command, "upgrade", boom)
    with pytest.raises(typer.Exit) as excinfo:
        init_cli._run_migrations(_repo_root_with_alembic_ini(tmp_path))
    assert excinfo.value.exit_code == 1
    out = capsys.readouterr().out
    assert "d2e3f4a5b6c7" in out
    assert "make db-reset CONFIRM=yes" in out
    assert "kestrel_dev" not in out  # the database password is never printed


def test_other_alembic_errors_propagate(monkeypatch, tmp_path) -> None:
    def boom(cfg, revision):
        raise CommandError("Target database is not up to date.")

    monkeypatch.setattr(init_cli.command, "upgrade", boom)
    with pytest.raises(CommandError):
        init_cli._run_migrations(_repo_root_with_alembic_ini(tmp_path))
