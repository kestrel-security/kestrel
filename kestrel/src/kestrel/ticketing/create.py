# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Create tracker issues from findings."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.ticket import FindingTicket, TicketIntegration
from kestrel.findings.handoff import build_handoff_package, handoff_markdown
from kestrel.findings.notes import add_note
from kestrel.ticketing.authoring import TicketAuthoringError, decrypt_integration_token
from kestrel.ticketing.protocol import TicketCreateRequest, TicketCreateResult
from kestrel.ticketing.registry import load_ticket_provider

# Cap how many tickets an org can create against one finding (abuse / noise).
MAX_TICKETS_PER_FINDING = 10


class TicketCreateError(ValueError):
    """Raised when ticket creation cannot proceed. Callers map to HTTP 4xx."""


def ticket_out(row: FindingTicket) -> dict[str, Any]:
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "ticket_integration_id": row.ticket_integration_id,
        "provider": row.provider,
        "external_id": row.external_id,
        "url": row.url,
        "created_by_operator_id": row.created_by_operator_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def list_finding_tickets(
    session: Session,
    finding: Finding,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(FindingTicket)
        .where(FindingTicket.finding_id == finding.id, FindingTicket.org_id == finding.org_id)
        .order_by(FindingTicket.created_at.desc(), FindingTicket.id.desc())
        .limit(max(0, min(limit, 100)))
    ).all()
    return [ticket_out(r) for r in rows]


def create_ticket_for_finding(
    session: Session,
    *,
    finding: Finding,
    integration: TicketIntegration,
    actor_operator_id: uuid.UUID,
    dry_run: bool = False,
    http_client: httpx.Client | None = None,
    add_note_on_success: bool = True,
) -> tuple[FindingTicket | None, TicketCreateResult, dict[str, Any] | None]:
    """Create an issue in the configured tracker from the finding handoff body.

    Returns ``(finding_ticket_or_none, result, note_out_or_none)``.
    When ``dry_run`` is True, no DB ticket/note rows are written.
    """
    if integration.org_id != finding.org_id:
        raise TicketCreateError("integration does not belong to this organization")
    if not integration.is_enabled:
        raise TicketCreateError("ticket integration is disabled")

    existing = (
        session.scalar(
            select(func.count())
            .select_from(FindingTicket)
            .where(FindingTicket.finding_id == finding.id, FindingTicket.org_id == finding.org_id)
        )
        or 0
    )
    if not dry_run and int(existing) >= MAX_TICKETS_PER_FINDING:
        raise TicketCreateError(f"finding already has {MAX_TICKETS_PER_FINDING} tickets; refuse further creates")

    package = build_handoff_package(session, finding)
    title = str(package.get("title") or finding.title)[:240]
    body = handoff_markdown(package)
    request = TicketCreateRequest(
        title=title,
        body=body,
        labels=["kestrel", f"severity:{finding.severity.value}"],
        finding_id=str(finding.id),
    )

    try:
        provider = load_ticket_provider(integration.provider)
        token = decrypt_integration_token(integration)
    except (TicketAuthoringError, ValueError) as exc:
        raise TicketCreateError(str(exc)) from exc

    try:
        result = provider.create_issue(
            token=token,
            config=dict(integration.config or {}),
            request=request,
            http_client=http_client,
            dry_run=dry_run,
        )
    except (TicketAuthoringError, ValueError) as exc:
        raise TicketCreateError(str(exc)) from exc
    except httpx.HTTPError as exc:
        # A tracker that is down or unreachable is the caller's 4xx, not an
        # unhandled 500. The message can carry the request URL, so scrub it.
        from kestrel.secrets.scrub import scrub_text

        reason = scrub_text(f"{type(exc).__name__}: {exc}", [token])
        raise TicketCreateError(f"ticket provider request failed: {reason}") from exc

    if dry_run:
        return None, result, None

    row = FindingTicket(
        id=uuid.uuid4(),
        org_id=finding.org_id,
        finding_id=finding.id,
        ticket_integration_id=integration.id,
        provider=integration.provider,
        external_id=result.external_id,
        url=result.url,
        created_by_operator_id=actor_operator_id,
    )
    session.add(row)
    session.flush()

    note_dict: dict[str, Any] | None = None
    if add_note_on_success:
        note = add_note(
            session,
            finding=finding,
            author_operator_id=actor_operator_id,
            body=f"Ticket created ({integration.provider}): {result.url}",
        )
        from kestrel.findings.notes import note_out

        note_dict = note_out(session, note)

    return row, result, note_dict
