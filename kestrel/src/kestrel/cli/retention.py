# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel retention trim-raw-source` -- redact old provenance payloads.
`kestrel retention prune-policy-evaluations` -- delete old evaluation history.

Both commands apply immediately; pass `--dry-run` to see the counts first.
Entities are never deleted, only their `raw_source` payload is replaced with a
tombstone (see kestrel.retention.raw_source).
"""

from __future__ import annotations

import typer
from sqlalchemy import select

from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.retention.policy_evaluations import DEFAULT_KEEP_PER_POLICY, prune_policy_evaluations
from kestrel.retention.raw_source import trim_raw_source

app = typer.Typer(help="Data retention maintenance.")


@app.command("trim-raw-source")
def trim_raw_source_cmd(
    older_than_days: int = typer.Option(..., "--older-than-days", help="Trim entities not seen in this many days."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be trimmed, change nothing."),
) -> None:
    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        result = trim_raw_source(session, org_id=org.id, older_than_days=older_than_days, dry_run=dry_run)
        if not dry_run:
            session.commit()
    except ValueError as exc:
        session.rollback()
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    verb = "Would trim" if result.dry_run else "Trimmed"
    typer.echo(f"{verb} raw_source for entities not seen since {result.cutoff.isoformat()}:")
    for model_name, count in sorted(result.trimmed_by_model.items()):
        if count:
            typer.echo(f"  {model_name}: {count}")
    typer.secho(f"{verb} {result.total} payload(s). No entities were deleted.", fg=typer.colors.GREEN)


@app.command("prune-policy-evaluations")
def prune_policy_evaluations_cmd(
    keep_per_policy: int = typer.Option(
        DEFAULT_KEEP_PER_POLICY,
        "--keep-per-policy",
        help="Newest evaluation rows to keep for each policy.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be deleted, change nothing."),
) -> None:
    """Delete old policy evaluation history, keeping the newest N per policy
    and every evaluation a finding still references."""
    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        result = prune_policy_evaluations(session, org_id=org.id, keep_per_policy=keep_per_policy, dry_run=dry_run)
        if not dry_run:
            session.commit()
    except ValueError as exc:
        session.rollback()
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    verb = "Would delete" if result.dry_run else "Deleted"
    typer.secho(
        f"{verb} {result.pruned} policy evaluation row(s), keeping the newest {result.keep_per_policy} per policy "
        "and any a finding references.",
        fg=typer.colors.GREEN,
    )
