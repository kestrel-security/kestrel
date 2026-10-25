# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Labeled identity risk factors for Identity Explorer detail.

Honest inputs only — not an opaque composite score. Reuses privileged-role,
open-finding, cross-app, and peer-outlier signals already used by reports.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.identity import Identity
from kestrel.reports.cross_app_privileged import _email_key, _privileged_role_rows
from kestrel.reports.peer_privilege import build_peer_privilege_items


def identity_risk_factors(
    db: Session,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
) -> dict[str, Any] | None:
    """Return labeled factors for one identity, or None if not in org."""
    identity = db.get(Identity, identity_id)
    if identity is None or identity.org_id != org_id:
        return None

    priv_rows = [r for r in _privileged_role_rows(db, org_id) if r.identity_id == identity_id]
    privileged_roles = sorted({r.role_name for r in priv_rows if r.role_name})
    privileged_role_count = len(privileged_roles)

    finding_rows = db.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.org_id == org_id,
            Finding.subject_id == identity_id,
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.severity)
    ).all()
    open_finding_count = 0
    open_critical = 0
    open_high = 0
    for severity, count in finding_rows:
        n = int(count)
        open_finding_count += n
        sev = severity.value if hasattr(severity, "value") else str(severity)
        if sev == "critical":
            open_critical += n
        elif sev == "high":
            open_high += n

    email_key = _email_key(identity.email)
    application_type_count = 1
    if email_key is not None:
        types: set[str] = set()
        for row in _privileged_role_rows(db, org_id):
            if _email_key(row.email) == email_key:
                types.add(row.application_type.value)
        # Include this identity's app type even without privileged roles.
        if identity.application_instance_id:
            inst = db.get(ApplicationInstance, identity.application_instance_id)
            if inst is not None:
                app = db.get(Application, inst.application_id)
                if app is not None:
                    types.add(app.application_type.value)
        application_type_count = max(1, len(types))

    peer: dict[str, Any] | None = None
    for item in build_peer_privilege_items(db, org_id):
        if item["identity_id"] == identity_id:
            peer = {
                "is_outlier": True,
                "peer_group_name": item["peer_group_name"],
                "peer_group_size": item["peer_group_size"],
                "peer_median_privileged_roles": item["peer_median_privileged_roles"],
                "privileged_role_count": item["privileged_role_count"],
                "excess_over_median": item["excess_over_median"],
                "explanation": item["explanation"],
            }
            break
    if peer is None:
        peer = {"is_outlier": False}

    factors: list[dict[str, Any]] = [
        {
            "id": "privileged_roles",
            "label": "Privileged roles",
            "value": privileged_role_count,
            "detail": (", ".join(privileged_roles) if privileged_roles else "No privileged roles on this identity"),
            "href": None,
        },
        {
            "id": "open_findings",
            "label": "Open findings",
            "value": open_finding_count,
            "detail": f"critical={open_critical}, high={open_high}",
            "href": f"/findings?status=open&subject_id={identity_id}",
        },
        {
            "id": "cross_app_span",
            "label": "Cross-app span (email-correlated)",
            "value": application_type_count,
            "detail": (
                f"{application_type_count} application type(s) sharing this email key"
                if email_key
                else "No email — span counted for this instance only"
            ),
            "href": None,
        },
        {
            "id": "peer_outlier",
            "label": "Peer-group privilege outlier",
            "value": 1 if peer.get("is_outlier") else 0,
            "detail": peer.get("explanation") or "Not an outlier vs shared member_of group median (or insufficient peers)",
            "href": None,
        },
    ]

    return {
        "kind": "kestrel.identity.risk_factors",
        "as_of": datetime.now(UTC).isoformat(),
        "identity_id": str(identity_id),
        "notes": (
            "Labeled inputs for investigation — not an opaque composite risk score. "
            "Peer outlier uses shared graph member_of groups, not job titles."
        ),
        "privileged_role_count": privileged_role_count,
        "privileged_roles": privileged_roles,
        "open_finding_count": open_finding_count,
        "open_critical": open_critical,
        "open_high": open_high,
        "application_type_count": application_type_count,
        "peer": peer,
        "factors": factors,
        "findings_list_path": f"/findings?status=open&subject_id={identity_id}",
    }
