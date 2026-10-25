# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel token create/list/revoke` -- manage long-lived API tokens for
CLI/automation use, independent of any browser session."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import typer
from sqlalchemy import select

from kestrel.auth.service import create_api_token, revoke_api_token
from kestrel.db.models.operator import ApiToken, Operator
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker

app = typer.Typer(help="Manage Kestrel API tokens.")


def _get_org(session):
    org = session.scalars(select(Organization)).first()
    if org is None:
        typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return org


def _get_operator(session, org, email: str) -> Operator:
    operator = session.scalars(select(Operator).where(Operator.org_id == org.id, Operator.email == email)).one_or_none()
    if operator is None:
        typer.secho(f"No operator found with email '{email}'.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return operator


@app.command("create")
def create_cmd(
    email: str = typer.Option(..., "--email", help="Email of the operator to create the token for."),
    name: str = typer.Option(..., "--name", help="A label for this token, e.g. 'ci-pipeline'."),
    expires_in_days: int = typer.Option(
        None, "--expires-in-days", min=1, max=365, help="1-365; omit for a token that never expires."
    ),
) -> None:
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _get_operator(session, org, email)
        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        token_row, raw_token = create_api_token(session, operator, name, expires_at=expires_at)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho(f"✓ Created token '{name}' for {email}", fg=typer.colors.GREEN)
    typer.secho(f"Token (shown once): {raw_token}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(f"  id: {token_row.id}")


@app.command("list")
def list_cmd(email: str = typer.Option(..., "--email", help="Email of the operator whose tokens to list.")) -> None:
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _get_operator(session, org, email)
        tokens = session.scalars(
            select(ApiToken).where(ApiToken.org_id == org.id, ApiToken.operator_id == operator.id)
        ).all()
    finally:
        session.close()

    for token in tokens:
        status = "revoked" if token.revoked_at else "active"
        typer.echo(f"{token.id}\t{token.name}\t{token.token_prefix}...\t{status}")


@app.command("revoke")
def revoke_cmd(token_id: uuid.UUID) -> None:
    session = get_sessionmaker()()
    try:
        token_row = session.get(ApiToken, token_id)
        if token_row is None:
            typer.secho(f"No token found with id '{token_id}'.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        revoke_api_token(token_row)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho(f"✓ Revoked token '{token_id}'", fg=typer.colors.GREEN)
