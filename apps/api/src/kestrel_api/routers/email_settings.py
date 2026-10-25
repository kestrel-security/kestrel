# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org mail server (SMTP) settings for outbound email.

Admin-only: the password is envelope-encrypted and never returned. Without
saved settings, email uses the deployment's ``KESTREL_SMTP_*`` environment,
which GET reports as ``source: "environment"``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.notifications.email_transport import EmailTransport
from kestrel.notifications.smtp_settings import (
    SmtpSettingsError,
    clear_org_smtp_settings,
    get_org_smtp_settings,
    resolve_smtp_config,
    settings_out,
    upsert_org_smtp_settings,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role

router = APIRouter(prefix="/settings/email", tags=["settings-email"])


class OrgEmailSettingsOut(BaseModel):
    host: str
    port: int
    security: str
    username: str | None = None
    password_configured: bool = False
    from_address: str
    is_enabled: bool
    updated_at: str | None = None


class EmailSettingsOut(BaseModel):
    source: str | None = None
    configured: bool
    host: str | None = None
    port: int | None = None
    security: str | None = None
    username: str | None = None
    password_configured: bool = False
    from_address: str | None = None
    is_enabled: bool = False
    updated_at: str | None = None
    org: OrgEmailSettingsOut | None = None
    default_ports: dict[str, int]


class EmailSettingsPutIn(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int
    security: str = Field(..., min_length=1, max_length=16)
    from_address: str = Field(..., min_length=3, max_length=320)
    username: str | None = Field(default=None, max_length=320)
    password: str | None = Field(default=None, max_length=1024)
    is_enabled: bool = True


class EmailTestOut(BaseModel):
    ok: bool
    source: str | None = None
    to: str | None = None
    detail: str | None = None


def _out(db: Session, org: Organization) -> EmailSettingsOut:
    return EmailSettingsOut(**settings_out(get_org_smtp_settings(db, org.id), resolve_smtp_config(db, org.id)))


@router.get("")
def get_email_settings(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> EmailSettingsOut:
    """The mail server in force (saved here or from the environment) and the saved settings."""
    return _out(db, org)


@router.put("")
def put_email_settings(
    body: EmailSettingsPutIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> EmailSettingsOut:
    """Save the organization's mail server; it overrides the environment's."""
    try:
        row, password_changed = upsert_org_smtp_settings(
            db,
            org_id=org.id,
            host=body.host,
            port=body.port,
            security=body.security,
            from_address=body.from_address,
            username=body.username,
            password=body.password,
            is_enabled=body.is_enabled,
        )
        db.flush()
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="settings.email_updated",
            target_type="org_smtp_settings",
            target_id=row.id,
            context={
                "host": row.host,
                "port": row.port,
                "security": row.security,
                "from_address": row.from_address,
                "username_set": row.username is not None,
                "is_enabled": row.is_enabled,
                "password_rotated": password_changed,
            },
        )
        db.commit()
    except SmtpSettingsError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _out(db, org)


@router.delete("")
def delete_email_settings(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, bool]:
    """Remove the saved mail server; email falls back to the environment, if set."""
    existing = get_org_smtp_settings(db, org.id)
    target_id = existing.id if existing else None
    cleared = clear_org_smtp_settings(db, org.id)
    if cleared:
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="settings.email_cleared",
            target_type="org_smtp_settings",
            target_id=target_id,
            context={},
        )
    db.commit()
    return {"cleared": cleared}


@router.post("/test")
def send_test_email(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> EmailTestOut:
    """Send a test message to the caller's own address through the mail server in force."""
    config = resolve_smtp_config(db, org.id)
    source = config.source if config else None
    to = (actor.email or "").strip() or None
    if config is None:
        return EmailTestOut(ok=False, source=None, to=to, detail="Email is not configured.")
    if to is None:
        return EmailTestOut(ok=False, source=source, to=None, detail="Your account has no email address.")

    result = EmailTransport(config=config).send(
        to=[to],
        subject="[Kestrel] Test email",
        text_body=(
            "This is a test message from Kestrel.\n\n"
            f"It was sent through {config.host}:{config.port} at the request of {to}. "
            "If you received it, notification emails, watched-finding digests and "
            "scheduled dashboard exports will be delivered.\n"
        ),
    )
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="settings.email_tested",
        target_type="org_smtp_settings",
        context={"ok": result.delivered, "source": source},
    )
    db.commit()
    return EmailTestOut(ok=result.delivered, source=source, to=to, detail=None if result.delivered else result.detail)
