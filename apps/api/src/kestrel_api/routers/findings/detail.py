# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Single-finding routes: detail, status/assignee patch, notes, provenance,
attack path, blast-radius export, remediation handoff, and verify.

Detail responses include policy remediation context, guided remediation
playbook steps, a resolved subject label, the finding's exception history,
investigation notes, activity timeline, related findings on the same subject,
evidence deep-links, and graph blast-radius neighbor findings. The handoff
export is markdown/JSON with optional create-issue URL templates (GitHub/Jira).
Mutating routes (PATCH, POST .../notes, POST .../verify) require at least the
analyst role; a note's `author` is always the authenticated caller.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from kestrel.audit.service import record_audit_event
from kestrel.db.models.finding import Finding, FindingSubjectType
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.findings.attack_path import ATTACK_PATH_DEPTH_DEFAULT, ATTACK_PATH_DEPTH_MAX, attack_path
from kestrel.findings.handoff import TicketUrlConfigError, apply_ticket_urls, build_handoff_package, handoff_markdown
from kestrel.findings.investigation.activity import activity_timeline
from kestrel.findings.investigation.blast_radius import (
    BLAST_RADIUS_DEPTH_DEFAULT,
    BLAST_RADIUS_DEPTH_MAX,
    blast_radius,
    blast_radius_findings_csv_rows,
    export_blast_radius,
)
from kestrel.findings.investigation.compliance import control_cross_links, policy_context
from kestrel.findings.investigation.evidence import evidence_with_links
from kestrel.findings.investigation.related import related_findings, same_policy_cohort
from kestrel.findings.investigation.status import list_exceptions
from kestrel.findings.investigation.subject import resolve_subject
from kestrel.findings.notes import NOTES_DETAIL_LIMIT, FindingNoteError, add_note, list_notes, note_out
from kestrel.findings.playbook import remediation_playbook
from kestrel.findings.verify import FindingVerifyError, verify_finding_remediation
from kestrel.findings.watchers import is_watching
from kestrel.security.csv_safe import csv_safe_row
from kestrel.ticketing.create import list_finding_tickets
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db, require_role
from kestrel_api.routers.findings._shared import _EXPORT_FORMATS, _apply_finding_patch, _summary
from kestrel_api.sync_trigger import enqueue_instance_sync
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingPatch(BaseModel):
    status: str | None = None
    # Use model_fields_set so null explicitly unassigns rather than meaning "no change".
    assigned_to_operator_id: uuid.UUID | None = None


class NoteIn(BaseModel):
    """Append-only investigation note body."""

    body: str = Field(min_length=1, max_length=4000)


class VerifyIn(BaseModel):
    """Optional sync enqueue after a successful live-inventory re-check."""

    trigger_sync: bool = False


def _detail(db: Session, finding: Finding, *, operator_id: uuid.UUID | None = None) -> dict:
    policy = policy_context(db, finding)
    subject = resolve_subject(db, finding)
    # An identity finding is about a person, not an account: the reviewer needs
    # to know the same human holds three other accounts before deciding what
    # "remove this access" means.
    if finding.subject_type is FindingSubjectType.IDENTITY and finding.subject_id:
        from kestrel.identities.correlate import identity_cluster_for

        cluster = identity_cluster_for(db, org_id=finding.org_id, identity_id=finding.subject_id)
        if cluster is not None:
            subject = {**subject, "cluster": cluster, "identity_path": f"/identities/{finding.subject_id}"}
    evidence = evidence_with_links(db, finding)
    out = {
        **_summary(db, finding),
        "evidence": evidence,
        "policy": policy,
        "subject": subject,
        "exceptions": list_exceptions(db, finding),
        "notes": list_notes(db, finding, limit=NOTES_DETAIL_LIMIT),
        "tickets": list_finding_tickets(db, finding),
        "activity": activity_timeline(db, finding),
        "related_findings": related_findings(db, finding),
        "same_policy_cohort": same_policy_cohort(db, finding),
        "control_cross_links": control_cross_links(db, finding),
        "blast_radius": blast_radius(db, finding),
        "attack_path": attack_path(db, finding),
        "remediation_playbook": remediation_playbook(
            remediation=policy.get("remediation") if policy else None,
            subject=subject,
            finding_status=finding.status.value,
            evidence_count=len(evidence),
            finding_id=str(finding.id),
        ),
    }
    if operator_id is not None:
        out["watching"] = is_watching(db, org_id=finding.org_id, operator_id=operator_id, finding_id=finding.id)
    return out


def _uuid_safe(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {k: _uuid_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_uuid_safe(v) for v in value]
    return value


@router.get("/{finding_id}/handoff")
def export_finding_handoff(
    finding_id: uuid.UUID,
    format: str = Query(default="markdown", description="markdown | json"),
    github_repo: str | None = Query(
        default=None,
        description="Optional owner/repo for GitHub Issues create URL",
    ),
    jira_base_url: str | None = Query(
        default=None,
        description=(
            "Optional https Create Issue base URL for Jira, e.g. "
            "https://jira.example.com/secure/CreateIssueDetails!init.jspa — "
            "summary/description query params are appended; SSRF-checked"
        ),
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> Response:
    """Ticket / chat remediation package.

    Markdown is paste-ready for Jira/Linear/Slack. JSON is the structured
    package (finding, subject, policy, evidence, playbook, ticket_urls).
    Optional ``github_repo`` / ``jira_base_url`` query params add create-issue
    URL templates only — not a ticketing adapter (see `ticket_integrations`).
    """
    fmt = format.strip().lower()
    if fmt not in {"markdown", "json", "md"}:
        raise HTTPException(status_code=422, detail="format must be markdown or json")
    if fmt == "md":
        fmt = "markdown"

    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    package = build_handoff_package(db, finding)
    try:
        apply_ticket_urls(
            package,
            github_repo=github_repo,
            jira_base_url=jira_base_url,
        )
    except TicketUrlConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    stamp = datetime.now(UTC).strftime("%Y%m%d")
    short_id = str(finding.id).replace("-", "")[:8]

    if fmt == "json":
        filename = f"kestrel-finding-handoff-{short_id}-{stamp}.json"
        body = _uuid_safe(package)
        return Response(
            content=json.dumps(body, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    filename = f"kestrel-finding-handoff-{short_id}-{stamp}.md"
    return Response(
        content=handoff_markdown(package),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{finding_id}/provenance")
def get_finding_provenance(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Subject raw_source browser for investigation.

    Returns redacted provider payload (or trim tombstone). Never includes
    connector secrets ciphertext/plaintext.
    """
    from kestrel.findings.provenance import finding_provenance_for_org

    payload = finding_provenance_for_org(db, org_id=org.id, finding_id=finding_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return payload


@router.get("/{finding_id}/attack-path")
def get_finding_attack_path(
    finding_id: uuid.UUID,
    depth: int = Query(
        default=ATTACK_PATH_DEPTH_DEFAULT,
        ge=1,
        le=ATTACK_PATH_DEPTH_MAX,
        description="Max graph hop depth for privilege-relevant BFS.",
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict[str, Any]:
    """Ordered attack-path hops over existing graph edges.

    Privilege-relevant BFS over real ``graph_edges`` only; each hop includes
    edge explainability. Never fabricates edges. Empty hops + honest summary
    when the subject has no graph node or no privilege sink within depth.
    """
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return attack_path(db, finding, max_depth=depth)


@router.get("/{finding_id}/blast-radius/export")
def export_finding_blast_radius(
    finding_id: uuid.UUID,
    format: str = Query(default="csv", description="csv | json"),
    depth: int = Query(
        default=BLAST_RADIUS_DEPTH_DEFAULT,
        ge=1,
        le=BLAST_RADIUS_DEPTH_MAX,
        description="Graph neighbor depth (same bounds as blast_radius).",
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> Response:
    """CSV/JSON export of blast-radius findings + graph subgraph.

    JSON includes the full incident package (`blast_radius` + `subgraph`
    nodes/edges). CSV flattens neighbor open findings for ticket handoff.
    """
    fmt = format.strip().lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(status_code=422, detail="format must be csv or json")

    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    payload = export_blast_radius(db, finding, depth=depth)
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    short_id = str(finding.id).replace("-", "")[:8]
    filename = f"kestrel-blast-radius-{short_id}-{stamp}.{fmt}"

    if fmt == "json":
        body = {
            "exported_at": datetime.now(UTC).isoformat(),
            **_uuid_safe(payload),
        }
        return Response(
            content=json.dumps(body, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    rows = blast_radius_findings_csv_rows(payload)
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "source_finding_id",
            "finding_id",
            "title",
            "severity",
            "status",
            "subject_type",
            "subject_id",
            "subject_label",
            "last_seen_at",
            "depth",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(
            csv_safe_row(
                {
                    "source_finding_id": str(row["source_finding_id"]),
                    "finding_id": str(row["finding_id"]),
                    "title": row["title"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "subject_type": row["subject_type"],
                    "subject_id": str(row["subject_id"]),
                    "subject_label": row.get("subject_label") or "",
                    "last_seen_at": row["last_seen_at"],
                    "depth": row.get("depth", ""),
                }
            )
        )
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _detail(db, finding, operator_id=operator.id)


@router.patch("/{finding_id}")
def patch_finding(
    finding_id: uuid.UUID,
    patch: FindingPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    webhook_delivery_ids: list = []
    _apply_finding_patch(
        db,
        finding=finding,
        org=org,
        actor=actor,
        status=patch.status,
        assign_set="assigned_to_operator_id" in patch.model_fields_set,
        assigned_to_operator_id=patch.assigned_to_operator_id,
        webhook_delivery_ids=webhook_delivery_ids,
    )
    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])
    return _summary(db, finding)


@router.get("/{finding_id}/notes")
def get_finding_notes(
    finding_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """List investigation notes for a finding, newest first."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"items": list_notes(db, finding, limit=limit)}


@router.post("/{finding_id}/notes", status_code=201)
def create_finding_note(
    finding_id: uuid.UUID,
    body: NoteIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Append an investigation note. Does not change finding status."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        note = add_note(
            db,
            finding=finding,
            author_operator_id=actor.id,
            body=body.body,
        )
    except FindingNoteError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    preview = note.body if len(note.body) <= 120 else note.body[:117] + "…"
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.note_added",
        target_type="finding",
        target_id=finding.id,
        context={
            "note_id": str(note.id),
            "body_preview": preview,
        },
    )
    db.commit()
    return note_out(db, note)


@router.post("/{finding_id}/verify")
def verify_finding_route(
    finding_id: uuid.UUID,
    body: VerifyIn | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    """Re-check remediation: dry-run policy for this subject.

    Does not mutate finding status. When ``trigger_sync`` is true and a
    connector instance is resolvable for the subject, enqueue a sync.
    """
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        result = verify_finding_remediation(db, finding)
    except FindingVerifyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    payload = body or VerifyIn()
    sync_enqueued: dict[str, Any] | None = None
    if payload.trigger_sync:
        instance_payload = result.get("connector_instance")
        if instance_payload is None:
            raise HTTPException(
                status_code=422,
                detail="No connector instance resolvable for this finding's subject",
            )
        from kestrel.db.models.connector import ConnectorInstance

        instance = db.get(ConnectorInstance, instance_payload["id"])
        if instance is None or instance.org_id != org.id:
            raise HTTPException(status_code=422, detail="Connector instance not found")
        # The same demo and already-running guards as "Sync now".
        task_id = enqueue_instance_sync(db, instance, tasks)
        sync_enqueued = {
            "connector_instance_id": str(instance.id),
            "task_id": task_id,
        }
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="connector_instance.sync_triggered",
            target_type="connector_instance",
            target_id=instance.id,
            context={"task_id": task_id, "via": "finding.verify"},
        )

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.verified",
        target_type="finding",
        target_id=finding.id,
        context={
            "result": result.get("result"),
            "trigger_sync": payload.trigger_sync,
            "sync_enqueued": sync_enqueued is not None,
        },
    )
    db.commit()

    out = {
        **result,
        "finding_id": str(result["finding_id"]),
        "policy": {
            **result["policy"],
            "id": str(result["policy"]["id"]),
        },
        "subject": {
            **result["subject"],
            "id": str(result["subject"]["id"]) if result["subject"].get("id") else None,
        },
        "sync_enqueued": sync_enqueued,
    }
    if out.get("connector_instance"):
        out["connector_instance"] = {
            **out["connector_instance"],
            "id": str(out["connector_instance"]["id"]),
            "application_instance_id": str(out["connector_instance"]["application_instance_id"]),
        }
    return out
