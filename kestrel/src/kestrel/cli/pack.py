# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel pack validate <dir>` / `kestrel pack install <dir>`."""

from __future__ import annotations

from pathlib import Path

import typer
from sqlalchemy import select

from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.policies.packs import install_pack, validate_pack

app = typer.Typer(help="Validate and install Kestrel Packs.")


@app.command("validate")
def validate_cmd(
    path: Path = typer.Argument(..., exists=True, file_okay=False, help="Pack directory (contains pack.yaml)."),
) -> None:
    """Validate pack.yaml + every policy module in a pack directory."""
    result = validate_pack(path)
    if result.is_valid:
        count = len(result.loaded_policies)
        typer.secho(
            f"✓ Pack '{result.pack_name}' is valid ({count} polic{'y' if count == 1 else 'ies'})",
            fg=typer.colors.GREEN,
        )
        return

    for policy_name, errors in result.errors.items():
        for e in errors:
            typer.secho(f"✗ {policy_name}: {e}", fg=typer.colors.RED)
    raise typer.Exit(code=1)


@app.command("install")
def install_cmd(path: Path) -> None:
    """Install a pack into the local organization's policy set (requires `kestrel init`)."""
    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        installed = install_pack(session, org.id, path)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    count = len(installed)
    typer.secho(f"✓ Installed {count} polic{'y' if count == 1 else 'ies'}", fg=typer.colors.GREEN)
