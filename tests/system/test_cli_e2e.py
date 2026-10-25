# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 -- CLI end-to-end vertical slice: ``kestrel init --seed`` -> sync
-> findings over HTTP.

Two absolute requirements this file exists to satisfy (see
``docs/testing.md`` and the qa-pipeline-engineer brief):

1. **Its own dedicated database.** ``kestrel init`` commits real rows
   through a session it builds itself (``get_sessionmaker()()``), not the
   test's rolled-back ``db_session`` savepoint -- so it must never run
   against the worker database shared with other integration tests. The
   ``dedicated_database_url`` fixture below creates and migrates a
   throwaway database and drops it on teardown.
2. **Never writes to ``REPO_ROOT/.env``.** ``kestrel init`` resolves every
   relative path (``.env``, ``alembic.ini``, ``migrations/``, ``packs/``)
   against ``Path.cwd()``. The ``sandbox_repo`` fixture builds a scratch
   directory under ``tmp_path`` that symlinks in the read-only pieces
   (alembic config, migrations, packs, ``.env.example``) so the CLI's
   relative-path logic resolves correctly while ``.env`` itself -- the one
   thing ``init`` writes -- is created fresh inside ``tmp_path``, never in
   the real repository.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
from kestrel.db.session import get_sessionmaker
from sqlalchemy import select

# `tests/system/_scratch_db.py` is a plain (non-test) sibling helper. Under
# `--import-mode=importlib` (see pyproject.toml) a bare `import _scratch_db`
# is not on sys.path, and this project deliberately avoids sys.path/conftest
# tricks to get sibling test modules importable -- see the import-mode note
# in pyproject.toml. Load it by file path instead.
_scratch_db_spec = importlib.util.spec_from_file_location(
    "kestrel_tests_system_scratch_db", Path(__file__).resolve().parent / "_scratch_db.py"
)
assert _scratch_db_spec is not None
assert _scratch_db_spec.loader is not None
_scratch_db = importlib.util.module_from_spec(_scratch_db_spec)
_scratch_db_spec.loader.exec_module(_scratch_db)
REPO_ROOT = _scratch_db.REPO_ROOT
scratch_database = _scratch_db.scratch_database

_SANDBOX_LINKS = ("alembic.ini", ".env.example", "migrations", "packs")


@pytest.fixture
def dedicated_database_url() -> str:
    with scratch_database(label="cli_e2e") as url:
        yield url


@pytest.fixture
def sandbox_repo(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox-repo"
    root.mkdir()
    for name in _SANDBOX_LINKS:
        source = REPO_ROOT / name
        if source.exists():
            (root / name).symlink_to(source, target_is_directory=source.is_dir())
    return root


def test_init_seed_sync_and_findings_over_http(dedicated_database_url, sandbox_repo, monkeypatch):
    # dedicated_database_url has already pointed DATABASE_URL (and reset the
    # memoized engine) at this test's own throwaway database.
    assert os.environ["DATABASE_URL"] == dedicated_database_url
    monkeypatch.chdir(sandbox_repo)

    real_env_path = REPO_ROOT / ".env"
    real_env_mtime_before = real_env_path.stat().st_mtime if real_env_path.exists() else None

    from kestrel.cli.main import app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(app, ["init", "--seed"])
    assert result.exit_code == 0, result.output

    # The one file `init` writes lands in the sandbox, never in the real repo.
    assert (sandbox_repo / ".env").exists()
    if real_env_mtime_before is not None:
        assert real_env_path.stat().st_mtime == real_env_mtime_before
    else:
        assert not real_env_path.exists()

    from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus
    from kestrel.db.models.finding import Finding
    from kestrel.db.models.org import Organization

    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).one()
        runs = session.scalars(select(ConnectorRun).where(ConnectorRun.org_id == org.id)).all()
        assert len(runs) == 1
        assert runs[0].status is ConnectorRunStatus.SUCCESS

        instance = session.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org.id)).one()

        # The seeded GitHub demo fixture is built specifically to trip at
        # least one shipped github-posture policy -- structural, not a
        # persona name: "seeding produces something to review."
        seeded_findings = session.scalars(select(Finding).where(Finding.org_id == org.id)).all()
        assert len(seeded_findings) >= 1
    finally:
        session.close()

    # `kestrel sync` (in-process) against the same instance: a second run of
    # the pipeline must stay a clean success.
    sync_result = runner.invoke(app, ["sync", "--instance", str(instance.id), "--connector", "github", "--no-async"])
    assert sync_result.exit_code == 0, sync_result.output

    session = get_sessionmaker()()
    try:
        from kestrel.testing import api_client

        org = session.get(Organization, org.id)
        client = api_client(session, org=org)
        response = client.get("/api/v1/findings")
        assert response.status_code == 200
        body = response.json()
        assert "items" in body
        assert len(body["items"]) >= 1
        first = body["items"][0]
        assert {"id", "status", "severity"} <= set(first)
    finally:
        session.close()
