# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel operator create/list/set-role/deactivate/set-password/reset-mfa` -- manage
Kestrel login accounts from the command line. `sync` and `init` stay
unauthenticated (they talk directly to Postgres via DATABASE_URL, already a
stronger trust boundary); only the network-facing API gets RBAC, so this
CLI is the escape hatch for managing that RBAC before a web UI login even
exists."""

from __future__ import annotations

import secrets as pysecrets
import uuid

import typer
from sqlalchemy import select

from kestrel.audit.service import record_audit_event
from kestrel.auth import mfa
from kestrel.auth.passwords import PasswordPolicyError, hash_password, validate_password_policy
from kestrel.auth.service import revoke_operator_api_tokens, revoke_operator_sessions
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker

app = typer.Typer(help="Manage Kestrel operator accounts.")


def _get_org(session):
    org = session.scalars(select(Organization)).first()
    if org is None:
        typer.secho("No organization configured -- run `kestrel init` first.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return org


@app.command("create")
def create_cmd(
    email: str,
    role: str = typer.Option("read_only", "--role", help="One of: read_only, analyst, admin."),
    password: str = typer.Option(None, "--password", help="Omit to auto-generate and print one once."),
    display_name: str = typer.Option(None, "--display-name"),
) -> None:
    """Create a login account; prints the generated password once."""
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        existing = session.scalars(select(Operator).where(Operator.org_id == org.id, Operator.email == email)).one_or_none()
        if existing is not None:
            typer.secho(f"An operator with email '{email}' already exists.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        try:
            role_enum = OperatorRole(role)
        except ValueError as exc:
            typer.secho(f"Invalid role '{role}' -- must be one of: read_only, analyst, admin", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc

        generated = password is None
        raw_password = password or pysecrets.token_urlsafe(18)
        if not generated:
            try:
                validate_password_policy(raw_password)
            except PasswordPolicyError as exc:
                typer.secho(str(exc), fg=typer.colors.RED)
                raise typer.Exit(code=1) from exc

        operator = Operator(
            id=uuid.uuid4(),
            org_id=org.id,
            email=email,
            display_name=display_name,
            password_hash=hash_password(raw_password),
            role=role_enum,
            is_active=True,
        )
        session.add(operator)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho(f"✓ Created operator '{email}' ({role_enum.value})", fg=typer.colors.GREEN)
    if generated:
        typer.secho(f"Generated password (shown once): {raw_password}", fg=typer.colors.YELLOW, bold=True)


@app.command("list")
def list_cmd() -> None:
    """List operators with role, status and last login."""
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operators = session.scalars(select(Operator).where(Operator.org_id == org.id).order_by(Operator.email)).all()
    finally:
        session.close()

    for op in operators:
        status = "active" if op.is_active else "deactivated"
        second_factor = "mfa" if mfa.is_enrolled(op) else "no-mfa"
        typer.echo(f"{op.email}\t{op.role.value}\t{status}\t{second_factor}")


def _find_operator(session, org, email: str) -> Operator:
    operator = session.scalars(select(Operator).where(Operator.org_id == org.id, Operator.email == email)).one_or_none()
    if operator is None:
        typer.secho(f"No operator found with email '{email}'.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return operator


@app.command("set-role")
def set_role_cmd(email: str, role: str) -> None:
    """Change an operator's role (read_only, analyst, admin)."""
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _find_operator(session, org, email)
        try:
            operator.role = OperatorRole(role)
        except ValueError as exc:
            typer.secho(f"Invalid role '{role}' -- must be one of: read_only, analyst, admin", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    typer.secho(f"✓ Set '{email}' to role {role}", fg=typer.colors.GREEN)


@app.command("deactivate")
def deactivate_cmd(email: str) -> None:
    """Disable sign-in for an operator; their sessions and tokens stop working at once."""
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _find_operator(session, org, email)
        operator.is_active = False
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    typer.secho(f"✓ Deactivated '{email}'", fg=typer.colors.GREEN)


@app.command("set-password")
def set_password_cmd(
    email: str,
    password: str = typer.Option(None, "--password", help="Omit to auto-generate and print one once."),
    keep_api_tokens: bool = typer.Option(
        False, "--keep-api-tokens", help="Leave the operator's API tokens valid (sessions are always revoked)."
    ),
) -> None:
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _find_operator(session, org, email)

        generated = password is None
        raw_password = password or pysecrets.token_urlsafe(18)
        if not generated:
            try:
                validate_password_policy(raw_password)
            except PasswordPolicyError as exc:
                typer.secho(str(exc), fg=typer.colors.RED)
                raise typer.Exit(code=1) from exc

        operator.password_hash = hash_password(raw_password)
        operator.failed_login_attempts = 0
        operator.locked_until = None
        # A reset is the break-glass path after a compromise: whoever held the
        # old password must not keep a session (or, by default, a token).
        revoked_sessions = revoke_operator_sessions(session, operator.id)
        revoked_tokens = 0 if keep_api_tokens else revoke_operator_api_tokens(session, operator.id)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho(f"✓ Password updated for '{email}'", fg=typer.colors.GREEN)
    typer.echo(f"  Revoked {revoked_sessions} session(s) and {revoked_tokens} API token(s).")
    if generated:
        typer.secho(f"Generated password (shown once): {raw_password}", fg=typer.colors.YELLOW, bold=True)


@app.command("reset-mfa")
def reset_mfa_cmd(email: str) -> None:
    """Remove an operator's two-factor authentication (lost device) and end their sessions."""
    session = get_sessionmaker()()
    try:
        org = _get_org(session)
        operator = _find_operator(session, org, email)
        revoked = mfa.reset(session, operator)
        record_audit_event(
            session,
            org_id=org.id,
            actor_operator_id=None,
            action="operator.mfa_reset",
            target_type="operator",
            target_id=operator.id,
            context={"sessions_revoked": revoked, "via": "cli"},
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho(f"✓ Two-factor authentication removed for '{email}'", fg=typer.colors.GREEN)
    typer.echo(f"  Revoked {revoked} session(s). They sign in with their password next time.")
