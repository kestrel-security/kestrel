# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel secrets status|rotate` -- see which master key wrote each stored
secret, and re-encrypt everything under the current one.

Rotation runbook (docs/deployment.md): set ``KESTREL_MASTER_KEY_PREVIOUS`` to
the retiring key and ``KESTREL_MASTER_KEY`` to the new one, restart the API
and worker, run ``kestrel secrets rotate``, confirm ``kestrel secrets status``
reports nothing stale, then unset the previous key. The same command, with no
key change, re-encrypts rows written before 0.4.0 so they gain associated
data."""

from __future__ import annotations

import typer

from kestrel.db.session import get_sessionmaker
from kestrel.secrets.crypto import (
    LEGACY_KEY_VERSION,
    MASTER_KEY_ENV,
    PREVIOUS_MASTER_KEY_ENV,
    EnvKeyProvider,
    MissingMasterKeyError,
)
from kestrel.secrets.rotation import rotate_all, rotation_status

app = typer.Typer(help="Inspect and rotate the master key that encrypts stored secrets.")


def _key_provider() -> EnvKeyProvider:
    try:
        return EnvKeyProvider()
    except (MissingMasterKeyError, ValueError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


def _describe(version: int, current: int, known: tuple[int, ...]) -> str:
    if version == LEGACY_KEY_VERSION:
        return "legacy (pre-0.4.0, no associated data)"
    if version == current:
        return f"current ({MASTER_KEY_ENV})"
    if version in known:
        return f"previous ({PREVIOUS_MASTER_KEY_ENV})"
    return "UNKNOWN KEY -- not readable by this process"


@app.command("status")
def status_cmd() -> None:
    """Count stored secrets by the master key that wrote them."""
    provider = _key_provider()
    session = get_sessionmaker()()
    try:
        status = rotation_status(session, provider)
    finally:
        session.close()

    typer.echo(f"Current master key id: {status.current_key_version}")
    if len(status.known_key_versions) > 1:
        others = [str(v) for v in status.known_key_versions if v != status.current_key_version]
        typer.echo(f"Previous master key id: {', '.join(others)}")
    typer.echo(f"Stored secrets: {status.total_rows}")
    for version, count in status.rows_by_key_version.items():
        typer.echo(f"  key {version}: {count}  {_describe(version, status.current_key_version, status.known_key_versions)}")
    for table, count in status.rows_by_table.items():
        typer.echo(f"  {table}: {count}")

    if status.unreadable_rows:
        typer.secho(
            f"{status.unreadable_rows} secret(s) were written with a key this process does not hold. "
            f"Set {PREVIOUS_MASTER_KEY_ENV} to that key and run `kestrel secrets rotate`.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    if status.stale_rows:
        typer.secho(
            f"{status.stale_rows} secret(s) are not under the current key; run `kestrel secrets rotate`.",
            fg=typer.colors.YELLOW,
        )
    else:
        typer.secho("Every stored secret is under the current key.", fg=typer.colors.GREEN)


@app.command("rotate")
def rotate_cmd(
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be re-encrypted; write nothing."),
    batch_size: int = typer.Option(200, "--batch-size", min=1, help="Rows per transaction."),
    if_needed: bool = typer.Option(False, "--if-needed", help="Exit 0 quietly when nothing is stale (for startup hooks)."),
) -> None:
    """Re-encrypt every stored secret under the current master key."""
    provider = _key_provider()
    session = get_sessionmaker()()
    try:
        before = rotation_status(session, provider)
        if if_needed and before.stale_rows == 0:
            return
        report = rotate_all(session, provider, batch_size=batch_size, dry_run=dry_run)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    verb = "Would re-encrypt" if dry_run else "Re-encrypted"
    typer.echo(f"{verb} {report.rotated} secret(s) under master key {report.current_key_version}")
    for table, count in sorted(report.rotated_by_table.items()):
        typer.echo(f"  {table}: {count}")
    if report.failed:
        typer.secho(f"{len(report.failed)} secret(s) could not be re-encrypted:", fg=typer.colors.RED)
        for failure in report.failed:
            typer.secho(f"  {failure.table} {failure.row_id}: {failure.error}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not dry_run:
        typer.secho(
            f"Done. If you were rotating keys, unset {PREVIOUS_MASTER_KEY_ENV} and restart the API and worker.",
            fg=typer.colors.GREEN,
        )
