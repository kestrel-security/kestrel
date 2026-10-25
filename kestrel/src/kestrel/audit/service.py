# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Real, user-attributed audit logging. Sibling to auth/, not folded into
it -- consumed well beyond login (finding changes, sync triggers, operator
management)."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from kestrel.db.models.audit import AuditLog


def record_audit_event(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor_operator_id: uuid.UUID | None,
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    context: dict | None = None,
) -> AuditLog:
    """Adds the row but does not commit -- participates in the caller's own
    transaction."""
    row = AuditLog(
        id=uuid.uuid4(),
        org_id=org_id,
        actor_operator_id=actor_operator_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        context=context,
    )
    session.add(row)
    return row
