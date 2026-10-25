# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy API: list/get installed policies, author custom Python policies
(Policy Workbench), enable/disable evaluation, and run fixture-backed tests.

Pack policies install via `POST /packs/{name}/install` / CLI / UI; their
source is file-owned. Custom policies (`source=custom`) are created and
versioned through this API. Enable/disable works for both.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
from kestrel.findings.pipeline import evaluate_policy_version
from kestrel.policies.authoring import (
    PolicyAuthoringError,
    activate_policy_version,
    create_custom_policy,
    fork_pack_policy,
    list_policy_versions,
    parse_policy_source,
    publish_new_version,
    set_current_version_enabled,
)
from kestrel.policies.custom_fixtures import (
    DEFAULT_CAPTURE_CAP,
    MAX_CAPTURE_CAP,
    CustomFixtureError,
    capture_fixture_from_live_matches,
    get_custom_fixtures,
    set_custom_fixtures,
)
from kestrel.policies.delete import SystemPolicyDeleteError, delete_policy
from kestrel.policies.dry_run import PolicyDryRunError, dry_run_policy, dry_run_source_text
from kestrel.policies.evaluations import DEFAULT_LIMIT, MAX_LIMIT, list_policy_evaluations
from kestrel.policies.generate import generate_policy_draft
from kestrel.policies.generate_context import generate_workbench_catalog
from kestrel.policies.listing import (
    DEFAULT_OPEN_FINDINGS_LIMIT,
    MAX_OPEN_FINDINGS_LIMIT,
    enrich_policy_summary,
    list_policy_summaries,
    policy_open_findings,
)
from kestrel.policies.packs import load_pack_fixture, resolve_pack_dir, resolve_pack_fixture_path
from kestrel.policies.testing import run_fixture_test_dict
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/policies", tags=["policies"])


def _summary(db: Session, p: Policy) -> dict:
    version = db.get(PolicyVersion, p.current_version_id) if p.current_version_id else None
    return enrich_policy_summary(db, p.org_id, p, version)


def _detail(db: Session, policy: Policy) -> dict:
    version = db.get(PolicyVersion, policy.current_version_id) if policy.current_version_id else None
    return {
        **enrich_policy_summary(db, policy.org_id, policy, version),
        "description": policy.description,
        "source_text": version.source_text if version else None,
        "remediation": version.remediation if version else None,
        "compliance_mappings": version.compliance_mappings if version else {},
    }


def _get_org_policy(db: Session, org: Organization, policy_id: uuid.UUID) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None or policy.org_id != org.id:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.get("")
def list_policies(db: Session = Depends(get_db), org: Organization = Depends(get_current_org)) -> list[dict]:
    """List installed policies with resource_type, open findings, and last eval."""
    return list_policy_summaries(db, org.id)


#: Policies are short modules; the cap keeps a pasted blob from tying up a worker.
MAX_POLICY_SOURCE_CHARS = 64 * 1024


class PolicySourceIn(BaseModel):
    source_text: str = Field(min_length=1, max_length=MAX_POLICY_SOURCE_CHARS)


class PolicyValidateErrorOut(BaseModel):
    message: str
    line: int | None = None
    column: int | None = None


class PolicyValidateOut(BaseModel):
    valid: bool
    errors: list[PolicyValidateErrorOut]
    slug: str | None = None
    severity: str | None = None
    description: str | None = None


@router.post("/validate")
def validate_policy_source(
    body: PolicySourceIn,
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> PolicyValidateOut:
    """Compile + validate Python policy without persisting."""
    parsed = parse_policy_source(body.source_text)
    contract = parsed.compiled.contract if parsed.compiled is not None else None
    return PolicyValidateOut(
        valid=parsed.is_valid,
        errors=[PolicyValidateErrorOut(message=err.message, line=err.line, column=err.column) for err in parsed.errors],
        slug=contract.policy_id if contract else None,
        severity=contract.severity if contract else None,
        description=contract.description if contract else None,
    )


class PolicyGenerateValidationOut(BaseModel):
    valid: bool
    errors: list[str]
    slug: str | None = None


class PolicyGenerateFixtureTestOut(BaseModel):
    passed: bool
    expected: list[str] = Field(default_factory=list)
    actual: list[str] = Field(default_factory=list)
    missing: list[str] | None = None
    unexpected: list[str] | None = None
    error: str | None = None


class PolicyGenerateIn(BaseModel):
    # Goes into a model prompt; a paragraph or two is plenty.
    intent: str = Field(min_length=1, max_length=4000)
    resource_type: str | None = None
    connector_hint: str | None = None
    application_instance_id: uuid.UUID | None = None
    include_fixtures: bool = True


class PolicyGenerateOut(BaseModel):
    source_text: str
    provider: str
    model: str
    message: str | None = None
    error: str | None = None
    validation: PolicyGenerateValidationOut
    fixtures: dict | None = None
    fixture_test: PolicyGenerateFixtureTestOut | None = None


@router.post("/generate")
def generate_policy(
    body: PolicyGenerateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> PolicyGenerateOut:
    """Return an AI, template, or unconfigured draft — never persists or enables.

    Always runs RestrictedPython validate after generate (optional one LLM repair
    pass on compile or fixture-test failure). ``include_fixtures`` defaults true and
    returns a connector-aligned match/non-match pair — never written to the DB.

    Uses org Settings → AI credentials when configured; falls back to
    ``KESTREL_LLM_*`` env; otherwise returns deterministic intent templates or
    ``provider=unconfigured`` (never a silent ``return True`` stub).
    """
    try:
        draft = generate_policy_draft(
            intent=body.intent,
            resource_type=body.resource_type,
            connector_hint=body.connector_hint,
            application_instance_id=body.application_instance_id,
            include_fixtures=body.include_fixtures,
            session=db,
            org_id=org.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PolicyGenerateOut(**draft)


@router.get("/generate/catalog")
def get_policy_generate_catalog(
    connector_hint: str | None = Query(default=None),
    application_instance_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Connector field catalog, intent chips, and redacted live samples for the Workbench."""
    return generate_workbench_catalog(
        db,
        org.id,
        connector_hint=connector_hint,
        application_instance_id=application_instance_id,
    )


@router.get("/{policy_id}")
def get_policy(policy_id: uuid.UUID, db: Session = Depends(get_db), org: Organization = Depends(get_current_org)) -> dict:
    return _detail(db, _get_org_policy(db, org, policy_id))


@router.get("/{policy_id}/fixtures")
def get_policy_fixtures(
    policy_id: uuid.UUID, db: Session = Depends(get_db), org: Organization = Depends(get_current_org)
) -> dict:
    """Return fixtures for Workbench prefill.

    Pack policies: on-disk ``*.fixtures.json``. Custom: ``Policy.fixtures`` JSONB
    when saved. Otherwise ``available=false`` (clients use RESOURCE_TYPE demos).
    """
    policy = _get_org_policy(db, org, policy_id)
    if policy.pack_name:
        path = resolve_pack_fixture_path(policy.pack_name, policy.slug)
        fixtures = load_pack_fixture(policy.pack_name, policy.slug)
        if fixtures is None or path is None:
            return {
                "available": False,
                "source": "none",
                "pack_name": policy.pack_name,
                "slug": policy.slug,
                "fixtures": None,
                "relative_path": None,
            }
        pack_dir = resolve_pack_dir(policy.pack_name)
        try:
            relative = str(path.relative_to(pack_dir)) if pack_dir is not None else path.name
        except ValueError:
            relative = path.name
        return {
            "available": True,
            "source": "pack",
            "pack_name": policy.pack_name,
            "slug": policy.slug,
            "fixtures": fixtures,
            "relative_path": relative,
        }

    custom = get_custom_fixtures(policy)
    if custom is not None:
        return {
            "available": True,
            "source": "custom",
            "pack_name": None,
            "slug": policy.slug,
            "fixtures": custom,
            "relative_path": None,
        }
    return {
        "available": False,
        "source": "none",
        "pack_name": None,
        "slug": policy.slug,
        "fixtures": None,
        "relative_path": None,
    }


class PolicyFixturesPut(BaseModel):
    fixtures: dict | None = None


@router.put("/{policy_id}/fixtures")
def put_policy_fixtures(
    policy_id: uuid.UUID,
    body: PolicyFixturesPut,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Save or clear custom policy fixtures. Pack policies → 400."""
    policy = _get_org_policy(db, org, policy_id)
    if policy.source != PolicySource.CUSTOM:
        raise HTTPException(
            status_code=400,
            detail="Fixtures can only be saved for custom policies (pack fixtures are file-owned)",
        )
    try:
        saved = set_custom_fixtures(policy, body.fixtures)
    except CustomFixtureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.fixtures_updated",
        target_type="policy",
        target_id=policy.id,
        context={
            "slug": policy.slug,
            "cleared": saved is None,
            "row_count": len(saved.get("rows", [])) if saved else 0,
        },
    )
    db.commit()
    db.refresh(policy)
    return {
        "available": saved is not None,
        "source": "custom" if saved is not None else "none",
        "pack_name": None,
        "slug": policy.slug,
        "fixtures": saved,
        "relative_path": None,
    }


class PolicyFixtureCaptureIn(BaseModel):
    source_text: str | None = Field(default=None, max_length=MAX_POLICY_SOURCE_CHARS)
    subject_ids: list[str] | None = None
    max_rows: int = Field(default=DEFAULT_CAPTURE_CAP, ge=1, le=MAX_CAPTURE_CAP)
    persist: bool = False


@router.post("/fixtures/from-matches")
def capture_fixtures_from_matches_draft(
    body: PolicyFixtureCaptureIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Build fixture JSON from live matches for unsaved draft source."""
    if not body.source_text or not body.source_text.strip():
        raise HTTPException(status_code=400, detail="source_text is required for draft capture")
    try:
        result = capture_fixture_from_live_matches(
            db,
            org.id,
            body.source_text,
            subject_ids=body.subject_ids,
            max_rows=body.max_rows,
        )
    except CustomFixtureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {**result, "persisted": False, "policy_id": None}


@router.post("/{policy_id}/fixtures/from-matches")
def capture_fixtures_from_matches(
    policy_id: uuid.UUID,
    body: PolicyFixtureCaptureIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Build fixture JSON from dry-run / live matches; optionally persist.

    Pack → 400 when ``persist=true``. Capture without persist is allowed for pack
    (read-only Workbench testing) but Save fixtures still requires custom.
    """
    policy = _get_org_policy(db, org, policy_id)
    source = body.source_text
    if not source or not source.strip():
        if policy.current_version_id is None:
            raise HTTPException(status_code=400, detail="Policy has no current version")
        version = db.get(PolicyVersion, policy.current_version_id)
        if version is None:
            raise HTTPException(status_code=400, detail="Policy has no current version")
        source = version.source_text

    try:
        result = capture_fixture_from_live_matches(
            db,
            org.id,
            source,
            subject_ids=body.subject_ids,
            max_rows=body.max_rows,
        )
    except CustomFixtureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    persisted = False
    if body.persist:
        if policy.source != PolicySource.CUSTOM:
            raise HTTPException(
                status_code=400,
                detail="Fixtures can only be saved for custom policies (pack fixtures are file-owned)",
            )
        try:
            set_custom_fixtures(policy, result["fixtures"])
        except CustomFixtureError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="policy.fixtures_updated",
            target_type="policy",
            target_id=policy.id,
            context={
                "slug": policy.slug,
                "cleared": False,
                "row_count": result["row_count"],
                "from_matches": True,
            },
        )
        db.commit()
        db.refresh(policy)
        persisted = True

    return {**result, "persisted": persisted, "policy_id": policy.id}


@router.get("/{policy_id}/evaluations")
def get_policy_evaluations(
    policy_id: uuid.UUID,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Recent PolicyEvaluation rows for this policy (newest first)."""
    policy = _get_org_policy(db, org, policy_id)
    items = list_policy_evaluations(db, org_id=org.id, policy_id=policy.id, limit=limit)
    return {"items": items, "limit": limit, "count": len(items)}


@router.get("/{policy_id}/findings")
def get_policy_open_findings(
    policy_id: uuid.UUID,
    limit: int = Query(DEFAULT_OPEN_FINDINGS_LIMIT, ge=1, le=MAX_OPEN_FINDINGS_LIMIT),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Open findings strip for policy detail.

    Returns org-scoped OPEN findings only (capped), severity rollup,
    ``ever_evaluated`` (any PolicyEvaluation vs never run), and a findings
    list deep-link. Reuses listing helpers for open counts.
    """
    policy = _get_org_policy(db, org, policy_id)
    return policy_open_findings(db, org.id, policy, limit=limit)


@router.post("", status_code=201)
def create_policy(
    body: PolicySourceIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    try:
        policy = create_custom_policy(
            db,
            org_id=org.id,
            source_text=body.source_text,
            created_by=actor.email,
        )
    except PolicyAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.created",
        target_type="policy",
        target_id=policy.id,
        context={"slug": policy.slug},
    )
    db.commit()
    db.refresh(policy)
    return _detail(db, policy)


@router.post("/{policy_id}/fork", status_code=201)
def fork_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Fork a pack policy into a new disabled custom policy.

    Pack source stays unchanged. Slug is unique (``{slug}-custom`` / collision
    suffixes); title indicates a fork. Analyst+.
    """
    policy = _get_org_policy(db, org, policy_id)
    try:
        forked = fork_pack_policy(db, policy=policy, created_by=actor.email)
    except PolicyAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.forked",
        target_type="policy",
        target_id=forked.id,
        context={
            "source_policy_id": str(policy.id),
            "source_slug": policy.slug,
            "forked_policy_id": str(forked.id),
            "forked_slug": forked.slug,
        },
    )
    db.commit()
    db.refresh(forked)
    return _detail(db, forked)


@router.post("/{policy_id}/versions", status_code=201)
def create_policy_version(
    policy_id: uuid.UUID,
    body: PolicySourceIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    policy = _get_org_policy(db, org, policy_id)
    try:
        version = publish_new_version(
            db,
            policy=policy,
            source_text=body.source_text,
            created_by=actor.email,
        )
    except PolicyAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.version_published",
        target_type="policy",
        target_id=policy.id,
        context={"version": version.version, "slug": policy.slug},
    )
    db.commit()
    db.refresh(policy)
    return _detail(db, policy)


@router.get("/{policy_id}/versions")
def get_policy_versions(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """List immutable PolicyVersion rows for this policy (newest first)."""
    policy = _get_org_policy(db, org, policy_id)
    items = list_policy_versions(db, policy=policy)
    return {
        "policy_id": policy.id,
        "policy_slug": policy.slug,
        "source": policy.source.value,
        "current_version_id": policy.current_version_id,
        "can_activate": policy.source.value == "custom",
        "items": items,
        "count": len(items),
    }


@router.post("/{policy_id}/versions/{version_id}/activate")
def activate_policy_version_endpoint(
    policy_id: uuid.UUID,
    version_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Set ``current_version_id`` to a prior immutable version (custom only).

    Pack policies → 400. Audit ``policy.version_activated``. Analyst+.
    """
    policy = _get_org_policy(db, org, policy_id)
    previous_version_id = policy.current_version_id
    try:
        version = activate_policy_version(db, policy=policy, version_id=version_id)
    except PolicyAuthoringError as exc:
        detail = str(exc)
        status = 404 if "not found" in detail.lower() else 400
        raise HTTPException(status_code=status, detail=detail) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.version_activated",
        target_type="policy",
        target_id=policy.id,
        context={
            "slug": policy.slug,
            "version_id": str(version.id),
            "version": version.version,
            "previous_version_id": str(previous_version_id) if previous_version_id else None,
        },
    )
    db.commit()
    db.refresh(policy)
    return _detail(db, policy)


class PolicyPatch(BaseModel):
    is_enabled: bool | None = None


@router.patch("/{policy_id}")
def patch_policy(
    policy_id: uuid.UUID,
    patch: PolicyPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    policy = _get_org_policy(db, org, policy_id)
    changes: dict = {}
    webhook_delivery_ids: list = []

    if patch.is_enabled is not None:
        try:
            # Disabling resolves the policy's open findings.
            set_current_version_enabled(
                db,
                policy=policy,
                is_enabled=patch.is_enabled,
                actor_operator_id=actor.id,
                webhook_delivery_ids=webhook_delivery_ids,
            )
        except PolicyAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        changes["is_enabled"] = patch.is_enabled

    if not changes:
        raise HTTPException(status_code=400, detail="no supported fields to update")

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.updated",
        target_type="policy",
        target_id=policy.id,
        context={"slug": policy.slug, **changes},
    )
    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])
    db.refresh(policy)
    return _detail(db, policy)


@router.delete("/{policy_id}", status_code=204)
def delete_policy_route(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> None:
    """Permanently delete a policy, its versions, evaluation history, and findings.

    Irreversible, unlike disabling. System policies answer 409. A deleted pack
    policy comes back (without findings) when its pack is installed again.
    """
    policy = _get_org_policy(db, org, policy_id)
    try:
        summary = delete_policy(db, policy=policy)
    except SystemPolicyDeleteError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.deleted",
        target_type="policy",
        target_id=policy_id,
        context=summary,
    )
    db.commit()


class FixtureTestIn(BaseModel):
    fixtures: dict
    source_text: str | None = Field(default=None, max_length=MAX_POLICY_SOURCE_CHARS)


@router.post("/{policy_id}/test")
def test_policy(
    policy_id: uuid.UUID,
    body: FixtureTestIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Runs fixtures against the current saved version, or against an
    unsaved `source_text` draft when provided (Workbench try-before-save)."""
    policy = _get_org_policy(db, org, policy_id)

    if body.source_text is not None:
        parsed = parse_policy_source(body.source_text)
        if not parsed.is_valid or parsed.compiled is None:
            raise HTTPException(status_code=400, detail="; ".join(str(e) for e in parsed.errors))
        source = body.source_text
    else:
        if policy.current_version_id is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        version = db.get(PolicyVersion, policy.current_version_id)
        if version is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        source = version.source_text

    try:
        result = run_fixture_test_dict(source, body.fixtures)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "passed": result.passed,
        "expected": sorted(result.expected_subject_ids),
        "actual": sorted(result.actual_subject_ids),
    }


@router.post("/test-draft")
def test_draft_policy(
    body: FixtureTestIn,
    _org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Fixture-test an unsaved draft (no policy id yet). Requires
    `source_text` in the body."""
    if not body.source_text:
        raise HTTPException(status_code=400, detail="source_text is required for draft tests")
    parsed = parse_policy_source(body.source_text)
    if not parsed.is_valid:
        raise HTTPException(status_code=400, detail="; ".join(str(e) for e in parsed.errors))
    try:
        result = run_fixture_test_dict(body.source_text, body.fixtures)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "passed": result.passed,
        "expected": sorted(result.expected_subject_ids),
        "actual": sorted(result.actual_subject_ids),
    }


class DryRunIn(BaseModel):
    source_text: str | None = Field(default=None, max_length=MAX_POLICY_SOURCE_CHARS)
    match_limit: int = Field(default=200, ge=1, le=200)


def _json_safe_dry_run(result: dict) -> dict:
    """Serialize UUID fields in a dry-run payload."""

    def _match(row: dict) -> dict:
        return {
            **row,
            "subject_id": str(row["subject_id"]) if row.get("subject_id") else None,
            "existing_finding_id": (str(row["existing_finding_id"]) if row.get("existing_finding_id") else None),
        }

    return {
        **result,
        "policy_id": str(result["policy_id"]) if result.get("policy_id") else None,
        "policy_version_id": (str(result["policy_version_id"]) if result.get("policy_version_id") else None),
        "matches": [_match(m) for m in result.get("matches") or []],
        "would_resolve": [_match(m) for m in result.get("would_resolve") or []],
    }


@router.post("/dry-run-draft")
def dry_run_draft_policy(
    body: DryRunIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Evaluate unsaved Python policy source against live inventory without writing findings."""
    if not body.source_text:
        raise HTTPException(status_code=400, detail="source_text is required for draft dry-run")
    parsed = parse_policy_source(body.source_text)
    if not parsed.is_valid:
        raise HTTPException(status_code=400, detail="; ".join(str(e) for e in parsed.errors))
    try:
        result = dry_run_source_text(
            db,
            org.id,
            body.source_text,
            match_limit=body.match_limit,
        )
    except PolicyDryRunError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _json_safe_dry_run(result)


@router.post("/{policy_id}/dry-run")
def dry_run_saved_policy(
    policy_id: uuid.UUID,
    body: DryRunIn | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Evaluate a policy (or optional draft source_text) against live inventory.

    Does not persist PolicyEvaluation rows or reconcile Findings. When a
    current version exists, matches are labeled `new` / `existing` and open
    findings no longer matching appear under `would_resolve`.
    """
    policy = _get_org_policy(db, org, policy_id)
    payload = body or DryRunIn()
    try:
        result = dry_run_policy(
            db,
            org.id,
            policy,
            source_text=payload.source_text,
            match_limit=payload.match_limit,
        )
    except PolicyDryRunError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _json_safe_dry_run(result)


@router.post("/{policy_id}/evaluate")
def evaluate_policy_now(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    """Run the current policy version and reconcile findings.

    Unlike sync (enabled-only) and dry-run (non-mutating), this evaluates the
    current version whether enabled or disabled, writes a ``PolicyEvaluation``,
    and reconciles findings. Webhook deliveries are enqueued after commit.
    """
    policy = _get_org_policy(db, org, policy_id)
    if policy.current_version_id is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    version = db.get(PolicyVersion, policy.current_version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    webhook_delivery_ids: list[uuid.UUID] = []
    evaluation = evaluate_policy_version(
        db,
        version,
        org.id,
        connector_run_id=None,
        webhook_delivery_ids=webhook_delivery_ids,
    )

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="policy.evaluated",
        target_type="policy",
        target_id=policy.id,
        context={
            "slug": policy.slug,
            "policy_version_id": str(version.id),
            "policy_version": version.version,
            "evaluation_id": str(evaluation.id),
            "status": evaluation.status.value,
            "matched_object_count": evaluation.matched_object_count,
            "is_enabled": version.is_enabled,
        },
    )
    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])

    return {
        "id": evaluation.id,
        "status": evaluation.status.value,
        "matched_object_count": evaluation.matched_object_count,
        "error_message": evaluation.error_message,
        "started_at": evaluation.started_at.isoformat() if evaluation.started_at else None,
        "finished_at": evaluation.finished_at.isoformat() if evaluation.finished_at else None,
        "policy_id": policy.id,
        "policy_slug": policy.slug,
        "policy_version_id": evaluation.policy_version_id,
        "policy_version": version.version,
        "is_enabled": version.is_enabled,
    }
