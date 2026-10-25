# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy context and compliance-control enrichment for a finding.

Resolves the policy version's compliance mappings to control catalog rows and
builds the control <-> finding cross-links (open, exception-backed and muted
peers under the same controls).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.policy import Policy, PolicyVersion


def enrich_compliance_controls(
    db: Session,
    org_id: uuid.UUID,
    mappings: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Resolve policy compliance mapping strings to control catalog rows.

    ``mappings`` shape: ``{ framework: [control_id, ...] }``. Built-in controls
    (``org_id`` null) are visible to every org; custom controls are org-scoped.
    """
    from kestrel.db.models.compliance import ComplianceControl, ComplianceFramework

    if not mappings:
        return []

    out: list[dict[str, Any]] = []
    for framework_raw, control_ids in mappings.items():
        framework_key = str(framework_raw).strip().lower()
        try:
            framework = ComplianceFramework(framework_key)
        except ValueError:
            # Keep unresolved entries so operators still see the mapping text.
            for cid in control_ids or []:
                out.append(
                    {
                        "framework": framework_key,
                        "control_id": str(cid),
                        "title": None,
                        "id": None,
                        "detail_path": None,
                        "resolved": False,
                    }
                )
            continue

        for cid in control_ids or []:
            control_id = str(cid).strip()
            if not control_id:
                continue
            control = db.scalars(
                select(ComplianceControl)
                .where(
                    ComplianceControl.framework == framework,
                    ComplianceControl.control_id == control_id,
                    (ComplianceControl.org_id == org_id) | (ComplianceControl.org_id.is_(None)),
                )
                .order_by(ComplianceControl.org_id.desc().nulls_last())
                .limit(1)
            ).first()
            if control is None:
                out.append(
                    {
                        "framework": framework.value,
                        "control_id": control_id,
                        "title": None,
                        "id": None,
                        "detail_path": None,
                        "resolved": False,
                    }
                )
                continue
            out.append(
                {
                    "framework": control.framework.value,
                    "control_id": control.control_id,
                    "title": control.title,
                    "id": str(control.id),
                    "detail_path": None,
                    "resolved": True,
                }
            )
    return out


def policy_context(db: Session, finding: Finding) -> dict | None:
    version = db.get(PolicyVersion, finding.policy_version_id)
    if version is None:
        return None
    policy = db.get(Policy, version.policy_id)
    mappings = version.compliance_mappings or {}
    controls = enrich_compliance_controls(db, finding.org_id, mappings)
    if policy is None:
        return {
            "id": None,
            "slug": None,
            "title": None,
            "description": None,
            "version": version.version,
            "version_id": version.id,
            "remediation": version.remediation,
            "compliance_mappings": mappings,
            "compliance_controls": controls,
        }
    return {
        "id": policy.id,
        "slug": policy.slug,
        "title": policy.title,
        "description": policy.description,
        "version": version.version,
        "version_id": version.id,
        "remediation": version.remediation,
        "compliance_mappings": mappings,
        "compliance_controls": controls,
        "source": policy.source.value,
        "is_system_toxic": policy.source.value == "system" and (policy.slug or "").startswith("system-toxic-"),
    }


def control_cross_links(
    db: Session,
    finding: Finding,
    *,
    peer_limit: int = 8,
) -> dict[str, Any]:
    """Exception / mute ↔ compliance-control investigation bridges.

    For each resolved control on this finding's policy, surface open peers,
    exception-backed peers, and muted peers — so GRC can jump control ↔ finding.
    """
    from kestrel.compliance.detail import (
        _findings_with_active_exceptions,
        _muted_findings,
        _open_findings,
        _policy_ids_for_control,
        _policy_version_ids,
        get_control_for_org,
    )

    version = db.get(PolicyVersion, finding.policy_version_id)
    mappings = version.compliance_mappings if version else None
    controls = enrich_compliance_controls(db, finding.org_id, mappings)
    cap = max(0, min(peer_limit, 12))
    out_controls: list[dict[str, Any]] = []
    for row in controls:
        if not row.get("resolved") or not row.get("id"):
            continue
        try:
            control_uuid = uuid.UUID(str(row["id"]))
        except ValueError:
            continue
        control = get_control_for_org(db, control_uuid, finding.org_id)
        if control is None:
            continue
        policy_ids = _policy_ids_for_control(db, control.id, finding.org_id)
        version_ids = _policy_version_ids(db, policy_ids)
        open_peers = [
            {
                "id": str(f["id"]),
                "title": f["title"],
                "severity": f["severity"],
                "status": f["status"],
                "detail_path": f"/findings/{f['id']}",
            }
            for f in _open_findings(db, org_id=finding.org_id, version_ids=version_ids, limit=cap + 1)
            if f["id"] != finding.id
        ][:cap]
        exception_peers = [
            {
                "id": str(f["id"]),
                "title": f["title"],
                "severity": f["severity"],
                "status": f["status"],
                "detail_path": f.get("detail_path") or f"/findings/{f['id']}",
            }
            for f in _findings_with_active_exceptions(db, org_id=finding.org_id, version_ids=version_ids, limit=cap + 1)
            if f["id"] != finding.id
        ][:cap]
        muted_peers = [
            {
                "id": str(f["id"]),
                "title": f["title"],
                "severity": f["severity"],
                "status": f["status"],
                "muted_until": f.get("muted_until"),
                "detail_path": f.get("detail_path") or f"/findings/{f['id']}",
            }
            for f in _muted_findings(db, org_id=finding.org_id, version_ids=version_ids, limit=cap + 1)
            if f["id"] != finding.id
        ][:cap]
        out_controls.append(
            {
                "id": str(control.id),
                "framework": control.framework.value,
                "control_id": control.control_id,
                "title": control.title,
                "detail_path": None,
                "open_peer_count": len(open_peers),
                "open_peers": open_peers,
                "exception_peer_count": len(exception_peers),
                "exception_peers": exception_peers,
                "muted_peer_count": len(muted_peers),
                "muted_peers": muted_peers,
            }
        )

    return {
        "kind": "kestrel.findings.control_cross_links",
        "controls": out_controls,
        "notes": (
            "Open, exception-backed, and muted findings for the same mapped "
            "compliance controls. Mute is temporary; exceptions are "
            "accepted-risk. Complements same-policy cohort."
        ),
    }
