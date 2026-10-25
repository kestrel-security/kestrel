# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""``kestrel init`` / ``kestrel demo up`` run inside a container.

The api image carries ``alembic.ini`` and ``migrations/`` but no
``.env.example``, runs as a non-root user that cannot write to its working
directory, and receives its configuration as environment variables. Bootstrap
must work there without writing a file, and must find the migrations even when
the working directory is somewhere else.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from kestrel.auth.dev_credentials import DEFAULT_DEV_ADMIN_PASSWORD
from kestrel.cli import init as init_cli


@pytest.fixture
def no_env_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("KESTREL_MASTER_KEY", raising=False)
    monkeypatch.delenv("KESTREL_ALEMBIC_INI", raising=False)


@pytest.fixture
def env_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kestrel:pw@postgres:5432/kestrel")
    monkeypatch.setenv("KESTREL_MASTER_KEY", "x" * 44)


def _write_ini(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    ini = directory / "alembic.ini"
    ini.write_text("[alembic]\nscript_location = migrations\n")
    return ini


def test_configured_environment_needs_no_env_file(env_config, tmp_path) -> None:
    init_cli._ensure_env_file(tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_checkout_without_config_writes_env_from_example(no_env_config, tmp_path) -> None:
    (tmp_path / ".env.example").write_text("DATABASE_URL=x\nKESTREL_MASTER_KEY=\n")

    init_cli._ensure_env_file(tmp_path)

    written = (tmp_path / ".env").read_text()
    assert "KESTREL_MASTER_KEY=\n" not in written
    assert "KESTREL_MASTER_KEY=" in written


def test_no_config_anywhere_exits_with_guidance(no_env_config, tmp_path, capsys) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        init_cli._ensure_env_file(tmp_path)

    assert excinfo.value.exit_code == 1
    assert "KESTREL_MASTER_KEY" in capsys.readouterr().out


def test_alembic_ini_from_explicit_setting_wins(no_env_config, monkeypatch, tmp_path) -> None:
    explicit = _write_ini(tmp_path / "elsewhere")
    _write_ini(tmp_path / "checkout")
    monkeypatch.setenv("KESTREL_ALEMBIC_INI", str(explicit))

    assert init_cli._resolve_alembic_ini(tmp_path / "checkout") == explicit


def test_alembic_ini_falls_back_to_the_image_directory(no_env_config, monkeypatch, tmp_path) -> None:
    image_ini = _write_ini(tmp_path / "app")
    monkeypatch.setattr(init_cli, "_IMAGE_APP_DIR", tmp_path / "app")

    assert init_cli._resolve_alembic_ini(tmp_path / "somewhere-else") == image_ini


def test_no_alembic_ini_exits(no_env_config, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(init_cli, "_IMAGE_APP_DIR", tmp_path / "missing")

    with pytest.raises(typer.Exit):
        init_cli._run_migrations(tmp_path)


def test_migrations_resolve_next_to_the_ini_not_the_cwd(no_env_config, monkeypatch, tmp_path) -> None:
    image_ini = _write_ini(tmp_path / "app")
    monkeypatch.setattr(init_cli, "_IMAGE_APP_DIR", tmp_path / "app")
    seen: dict[str, str] = {}
    monkeypatch.setattr(
        init_cli.command, "upgrade", lambda cfg, revision: seen.update(loc=cfg.get_main_option("script_location"))
    )

    init_cli._run_migrations(tmp_path / "cwd")

    assert seen["loc"] == str(image_ini.parent / "migrations")


def test_a_checkout_keeps_writing_env_even_with_config_exported(env_config, tmp_path) -> None:
    (tmp_path / ".env.example").write_text("KESTREL_MASTER_KEY=\n")

    init_cli._ensure_env_file(tmp_path)

    assert (tmp_path / ".env").exists()


# `kestrel-dev-password` is published in this repository. A checkout uses it
# only when asked (`--dev-password`, `kestrel demo up`); a deployment must never
# be bootstrapped with it.


def test_deployment_admin_gets_a_random_password(env_config, tmp_path) -> None:
    password = init_cli._admin_password_for(tmp_path, None)

    assert password is not None
    assert password != DEFAULT_DEV_ADMIN_PASSWORD
    assert password != init_cli._admin_password_for(tmp_path, None)


def test_checkout_admin_gets_a_random_password_by_default(env_config, tmp_path) -> None:
    (tmp_path / ".env.example").write_text("")

    password = init_cli._admin_password_for(tmp_path, None)

    assert password is not None
    assert password != DEFAULT_DEV_ADMIN_PASSWORD


def test_checkout_admin_keeps_the_local_default_when_asked(env_config, tmp_path) -> None:
    (tmp_path / ".env.example").write_text("")

    assert init_cli._admin_password_for(tmp_path, None, dev_default=True) is None


def test_deployment_ignores_the_local_default_request(env_config, tmp_path) -> None:
    password = init_cli._admin_password_for(tmp_path, None, dev_default=True)

    assert password is not None
    assert password != DEFAULT_DEV_ADMIN_PASSWORD


def test_an_explicit_password_always_wins(env_config, tmp_path) -> None:
    assert init_cli._admin_password_for(tmp_path, "a-chosen-Passw0rd!") == "a-chosen-Passw0rd!"
