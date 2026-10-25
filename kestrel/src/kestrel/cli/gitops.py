# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel export` / `kestrel plan` / `kestrel apply` (GitOps)."""

from __future__ import annotations

from pathlib import Path

import typer
from sqlalchemy import select

from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.gitops.apply import apply_manifest
from kestrel.gitops.diff import compute_plan
from kestrel.gitops.export import export_org_state
from kestrel.gitops.manifest import GitOpsError, load_manifest

app = typer.Typer(help="GitOps desired-state: export, plan (CI), apply.")


def _org_session():
    session = get_sessionmaker()()
    org = session.scalars(select(Organization)).first()
    if org is None:
        session.close()
        typer.secho("No organization configured — run `kestrel init` first.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return session, org


@app.command("export")
def export_cmd(
    output: Path = typer.Option(
        Path("gitops-out"),
        "--output",
        "-o",
        help="Directory to write kestrel.yaml + policies/.",
    ),
) -> None:
    """Export current org desired state (secrets never included as values)."""
    session, org = _org_session()
    try:
        try:
            export_org_state(session, org.id, output)
        except GitOpsError as exc:
            typer.secho(f"✗ {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        typer.secho(f"✓ Wrote {output / 'kestrel.yaml'}", fg=typer.colors.GREEN)
    finally:
        session.close()


@app.command("plan")
def plan_cmd(
    manifest: Path = typer.Argument(..., help="Path to DesiredState YAML or directory with kestrel.yaml."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable plan."),
) -> None:
    """Diff manifest vs DB. Exit 1 on drift (CI-safe). Exit 0 when in sync."""
    session, org = _org_session()
    try:
        try:
            desired = load_manifest(manifest)
        except GitOpsError as exc:
            typer.secho(f"✗ {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        result = compute_plan(session, org.id, desired)
        if json_out:
            typer.echo(result.to_json())
        else:
            typer.echo(result.format_human())
        raise typer.Exit(code=result.exit_code)
    finally:
        session.close()


@app.command("apply")
def apply_cmd(
    manifest: Path = typer.Argument(..., help="Path to DesiredState YAML or directory with kestrel.yaml."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show actions without writing."),
) -> None:
    """Idempotently apply packs, custom policies, connectors, exceptions.

    Secrets listed under `secrets[].ref` are never applied from YAML.
    """
    session, org = _org_session()
    try:
        try:
            desired = load_manifest(manifest)
        except GitOpsError as exc:
            typer.secho(f"✗ {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        result = apply_manifest(session, org.id, desired, dry_run=dry_run)
        for item in result.applied:
            typer.secho(f"  + {item}", fg=typer.colors.GREEN)
        for item in result.skipped:
            typer.echo(f"  · {item}")
        for warn in result.warnings:
            typer.secho(f"  ! {warn}", fg=typer.colors.YELLOW)
        for err in result.errors:
            typer.secho(f"  ✗ {err}", fg=typer.colors.RED)
        if result.errors:
            session.rollback()
            raise typer.Exit(code=1)
        if not dry_run:
            session.commit()
            typer.secho("✓ Apply complete", fg=typer.colors.GREEN)
        else:
            typer.secho("✓ Dry-run complete (no changes)", fg=typer.colors.GREEN)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
