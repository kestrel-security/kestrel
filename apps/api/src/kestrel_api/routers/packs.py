# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack catalog API: list installable packs from disk and install into the
current org. Pack policies remain file-owned; this is the HTTP
equivalent of `kestrel pack install`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.policies.coverage import pack_coverage_for_name
from kestrel.policies.packs import (
    disable_pack,
    enable_pack,
    install_pack,
    list_available_packs,
    pack_catalog_detail,
    preview_pack_install,
    resolve_pack_dir,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/packs", tags=["packs"])


class PackInstallRequest(BaseModel):
    profile: str | None = Field(
        default=None,
        description="Install only policies matching this profile (level_1, level_2, monitor)",
    )


def _policy_summary(db: Session, p: Policy) -> dict:
    version = db.get(PolicyVersion, p.current_version_id) if p.current_version_id else None
    return {
        "id": p.id,
        "slug": p.slug,
        "title": p.title,
        "source": p.source.value,
        "pack_name": p.pack_name,
        "current_version_id": p.current_version_id,
        "version": version.version if version else None,
        "severity": version.severity.value if version else None,
        "is_enabled": version.is_enabled if version else None,
    }


def _installed_pack_names(db: Session, org_id) -> set[str]:
    rows = db.scalars(
        select(Policy.pack_name).where(Policy.org_id == org_id, Policy.pack_name.is_not(None)).distinct()
    ).all()
    return {name for name in rows if name}


def _pack_summary_dict(pack, installed_names: set[str]) -> dict:
    return {
        "name": pack.name,
        "version": pack.version,
        "description": pack.description,
        "policy_count": pack.policy_count,
        "policy_slugs": list(pack.policy_slugs),
        "installed": pack.name in installed_names,
        "detail_path": f"/policies/packs/{pack.name}",
        "display_name": pack.display_name or pack.name,
        "summary": pack.summary or "",
        "application": pack.application,
        "categories": list(pack.categories),
        "frameworks": list(pack.frameworks),
        "vendor_baselines": list(pack.vendor_baselines),
    }


@router.get("")
def list_packs(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> list[dict]:
    """Lists packs discoverable under `KESTREL_PACKS_DIR` (default `./packs`)."""
    installed = _installed_pack_names(db, org.id)
    return [_pack_summary_dict(pack, installed) for pack in list_available_packs()]


@router.get("/{name}")
def get_pack(
    name: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Pack marketplace detail: policy titles/severities from disk."""
    detail = pack_catalog_detail(name)
    if detail is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pack '{name}' not found in catalog",
        )
    installed_names = _installed_pack_names(db, org.id)
    installed = name in installed_names
    slugs = [row["slug"] for row in detail["policies"]]
    installed_policies = (
        list(db.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug.in_(slugs))).all()) if slugs else []
    )
    by_slug = {p.slug: p for p in installed_policies}
    policies_out = []
    for row in detail["policies"]:
        installed_row = by_slug.get(row["slug"])
        policies_out.append(
            {
                **row,
                "installed": installed_row is not None,
                "policy_id": str(installed_row.id) if installed_row else None,
                "policy_path": f"/policies/{installed_row.id}" if installed_row else None,
            }
        )
    return {
        **detail,
        "installed": installed,
        "policies": policies_out,
        "detail_path": f"/policies/packs/{name}",
    }


@router.get("/{name}/coverage")
def get_pack_coverage(
    name: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    coverage = pack_coverage_for_name(db, org.id, name)
    if coverage is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pack '{name}' not found in catalog",
        )
    return coverage.to_dict()


@router.get("/{name}/install-preview")
def preview_named_pack_install(
    name: str,
    profile: str | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Diff on-disk pack policies vs org-installed (by slug) before install.

    Returns `added` / `updated` / `unchanged` slug lists. Updated means source
    text, severity, or title differs from the org's current version.
    """
    pack_dir = resolve_pack_dir(name)
    if pack_dir is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pack '{name}' not found in catalog",
        )

    try:
        preview = preview_pack_install(db, org.id, pack_dir, profile=profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return preview.to_dict()


@router.post("/{name}/install", status_code=200)
def install_named_pack(
    name: str,
    body: PackInstallRequest | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> list[dict]:
    """Installs (or re-installs) a catalog pack into the current org.

    Idempotent: unchanged policy source text does not create a new version.
    Policies are always scoped to `org.id`. Prefer `GET …/install-preview`
    before re-install so operators can confirm the diff.
    """
    pack_dir = resolve_pack_dir(name)
    if pack_dir is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pack '{name}' not found in catalog",
        )

    profile = body.profile if body else None
    try:
        installed = install_pack(db, org.id, pack_dir, profile=profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="pack.installed",
        target_type="pack",
        target_id=None,
        context={
            "pack_name": name,
            "pack_dir": str(pack_dir),
            "policy_count": len(installed),
            "policy_slugs": [p.slug for p in installed],
        },
    )
    db.commit()
    return [_policy_summary(db, p) for p in installed]


@router.post("/{name}/enable", status_code=200)
def enable_named_pack(
    name: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    if resolve_pack_dir(name) is None:
        raise HTTPException(status_code=404, detail=f"Pack '{name}' not found")
    count = enable_pack(db, org.id, name)
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="pack.enabled",
        target_type="pack",
        target_id=None,
        context={"pack_name": name, "policies_updated": count},
    )
    db.commit()
    return {"pack_name": name, "policies_updated": count, "enabled": True}


@router.post("/{name}/disable", status_code=200)
def disable_named_pack(
    name: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    if resolve_pack_dir(name) is None:
        raise HTTPException(status_code=404, detail=f"Pack '{name}' not found")
    webhook_delivery_ids: list = []
    # Disabling resolves each policy's open findings.
    count = disable_pack(db, org.id, name, actor_operator_id=actor.id, webhook_delivery_ids=webhook_delivery_ids)
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="pack.disabled",
        target_type="pack",
        target_id=None,
        context={"pack_name": name, "policies_updated": count},
    )
    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])
    return {"pack_name": name, "policies_updated": count, "enabled": False}
