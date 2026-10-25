# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel audit list` -- read the audit trail from the host, without an API
token or a running API.

Deliberately read-only: `audit_log` is append-only, and a CLI that could
edit or delete audit rows would defeat the point of keeping them.
"""

from __future__ import annotations

import typer
from sqlalchemy import select

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker

app = typer.Typer(help="Inspect the audit trail.")


@app.command("list")
def list_cmd(
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum rows to show (most recent first)."),
    action: str | None = typer.Option(None, "--action", help="Filter by exact action, e.g. finding.updated."),
    actor: str | None = typer.Option(None, "--actor", help="Filter by actor email."),
) -> None:
    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        stmt = select(AuditLog).where(AuditLog.org_id == org.id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if actor:
            operator = session.scalars(select(Operator).where(Operator.email == actor)).one_or_none()
            if operator is None:
                typer.secho(f"No operator with email {actor!r}", fg=typer.colors.RED)
                raise typer.Exit(code=1)
            stmt = stmt.where(AuditLog.actor_operator_id == operator.id)

        rows = session.scalars(stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)).all()
        if not rows:
            typer.echo("No audit events matched.")
            return

        for row in rows:
            operator = session.get(Operator, row.actor_operator_id) if row.actor_operator_id else None
            # "-" rather than a made-up name: some actions (a failed login for
            # an unknown email) genuinely have no actor.
            who = operator.email if operator else "-"
            target = f" {row.target_type}:{row.target_id}" if row.target_type else ""
            typer.echo(f"{row.created_at.isoformat()}  {who:32}  {row.action}{target}")
    finally:
        session.close()
