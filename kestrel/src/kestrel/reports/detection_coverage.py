# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Detection coverage gaps report.

Compares connected application instances to enabled policies that appear
applicable to each application type. Labeled gap kinds — not an opaque score.

Applicability heuristics (no Policy→Application FK):
- slug prefixes: ``github-``, ``gws-``, ``slack-``, ``okta-``
- source_text markers: ``application.type == "<type>"``
- ``cross-app-`` / ``cross_app`` policies counted separately (not instance gaps)
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.finding import Finding
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
from kestrel.db.models.resource import Resource

EXPORT_MAX = 5000

# ApplicationType.value → slug prefixes that typically target that SaaS.
_SLUG_PREFIXES: dict[str, tuple[str, ...]] = {
    ApplicationType.GITHUB.value: ("github-",),
    ApplicationType.GOOGLE_WORKSPACE.value: ("gws-", "google-workspace-", "google_workspace-"),
    ApplicationType.SLACK.value: ("slack-",),
    ApplicationType.OKTA.value: ("okta-",),
    ApplicationType.CUSTOM.value: (),
}

_TYPE_IN_SOURCE = re.compile(
    r'application\.type\s*==\s*"(github|google_workspace|slack|okta|custom)"',
    re.IGNORECASE,
)


def _is_cross_app(slug: str, source_text: str) -> bool:
    slug_l = slug.lower()
    if slug_l.startswith("cross-app") or slug_l.startswith("cross_app"):
        return True
    return "cross-app" in source_text.lower() or "cross_app" in source_text.lower()


def _policy_app_types(slug: str, source_text: str) -> set[str]:
    """Infer which ApplicationType values a policy targets."""
    if _is_cross_app(slug, source_text):
        return set()  # handled separately as cross_app_policy_count

    types: set[str] = set()
    slug_l = slug.lower()
    for app_type, prefixes in _SLUG_PREFIXES.items():
        if any(slug_l.startswith(p) for p in prefixes):
            types.add(app_type)

    for match in _TYPE_IN_SOURCE.finditer(source_text):
        types.add(match.group(1).lower())

    return types


def _gap_kind(*, applicable_enabled: int, policies_with_findings: int) -> str:
    if applicable_enabled == 0:
        return "no_policies"
    if policies_with_findings == 0:
        return "never_matched"
    return "covered"


def detection_coverage_report(
    db: Session,
    org_id: uuid.UUID,
    *,
    limit: int = EXPORT_MAX,
    gap_only: bool = False,
) -> dict[str, Any]:
    """Per application-instance detection coverage vs enabled policies."""
    instances = list(
        db.scalars(
            select(ApplicationInstance)
            .where(ApplicationInstance.org_id == org_id)
            .order_by(ApplicationInstance.display_name)
        ).all()
    )
    if not instances:
        return {
            "as_of": datetime.now(UTC).isoformat(),
            "total_instances": 0,
            "gap_count": 0,
            "cross_app_policy_count": 0,
            "truncated": False,
            "items": [],
        }

    apps = {
        a.id: a
        for a in db.scalars(
            select(Application).where(
                Application.org_id == org_id,
                Application.id.in_([i.application_id for i in instances]),
            )
        ).all()
    }

    instance_ids = [i.id for i in instances]
    identity_counts: dict[uuid.UUID, int] = {
        row[0]: int(row[1])
        for row in db.execute(
            select(Identity.application_instance_id, func.count())
            .where(Identity.org_id == org_id, Identity.application_instance_id.in_(instance_ids))
            .group_by(Identity.application_instance_id)
        ).all()
    }
    resource_counts: dict[uuid.UUID, int] = {
        row[0]: int(row[1])
        for row in db.execute(
            select(Resource.application_instance_id, func.count())
            .where(Resource.org_id == org_id, Resource.application_instance_id.in_(instance_ids))
            .group_by(Resource.application_instance_id)
        ).all()
    }
    oauth_counts: dict[uuid.UUID, int] = {
        row[0]: int(row[1])
        for row in db.execute(
            select(OAuthApplication.application_instance_id, func.count())
            .where(
                OAuthApplication.org_id == org_id,
                OAuthApplication.application_instance_id.in_(instance_ids),
            )
            .group_by(OAuthApplication.application_instance_id)
        ).all()
    }

    policies = list(
        db.scalars(
            select(Policy).where(
                Policy.org_id == org_id,
                Policy.source != PolicySource.SYSTEM,
            )
        ).all()
    )
    version_ids = [p.current_version_id for p in policies if p.current_version_id]
    versions: dict[uuid.UUID, PolicyVersion] = {}
    if version_ids:
        for pv in db.scalars(select(PolicyVersion).where(PolicyVersion.id.in_(version_ids))).all():
            versions[pv.id] = pv

    # policy_id → finding count (any status)
    finding_counts: dict[uuid.UUID, int] = defaultdict(int)
    if version_ids:
        for policy_id, count in db.execute(
            select(PolicyVersion.policy_id, func.count())
            .select_from(Finding)
            .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
            .where(Finding.org_id == org_id, PolicyVersion.policy_id.in_([p.id for p in policies]))
            .group_by(PolicyVersion.policy_id)
        ).all():
            finding_counts[policy_id] = int(count)

    # app_type → list of applicable enabled policies
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cross_app_enabled = 0
    for policy in policies:
        current = versions.get(policy.current_version_id) if policy.current_version_id else None
        if current is None or not current.is_enabled:
            continue
        source_text = current.source_text or ""
        if _is_cross_app(policy.slug, source_text):
            cross_app_enabled += 1
            continue
        for app_type in _policy_app_types(policy.slug, source_text):
            by_type[app_type].append(
                {
                    "policy_id": policy.id,
                    "slug": policy.slug,
                    "title": policy.title,
                    "finding_count": finding_counts.get(policy.id, 0),
                }
            )

    items: list[dict[str, Any]] = []
    for instance in instances:
        application = apps.get(instance.application_id)
        app_type = application.application_type.value if application else ApplicationType.CUSTOM.value
        applicable = by_type.get(app_type, [])
        enabled_count = len(applicable)
        with_findings = sum(1 for p in applicable if p["finding_count"] > 0)
        kind = _gap_kind(applicable_enabled=enabled_count, policies_with_findings=with_findings)
        if gap_only and kind == "covered":
            continue

        entity_counts = {
            "identities": int(identity_counts.get(instance.id, 0)),
            "resources": int(resource_counts.get(instance.id, 0)),
            "oauth_applications": int(oauth_counts.get(instance.id, 0)),
        }
        sample_slugs = [p["slug"] for p in applicable[:5]]
        items.append(
            {
                "application_instance_id": instance.id,
                "display_name": instance.display_name,
                "application_type": app_type,
                "entity_counts": entity_counts,
                "applicable_policy_count": enabled_count,
                "policies_with_findings": with_findings,
                "gap_kind": kind,
                "sample_policy_slugs": sample_slugs,
                "policies_path": "/policies",
                "gap_detail": (
                    "No enabled policies target this application type"
                    if kind == "no_policies"
                    else (
                        "Enabled policies exist but have never produced findings"
                        if kind == "never_matched"
                        else "At least one applicable policy has produced findings"
                    )
                ),
            }
        )

    items.sort(
        key=lambda row: (
            0 if row["gap_kind"] == "no_policies" else 1 if row["gap_kind"] == "never_matched" else 2,
            -sum(row["entity_counts"].values()),
            str(row["display_name"]).lower(),
        )
    )
    gap_count = sum(1 for row in items if row["gap_kind"] != "covered")
    # When gap_only, gap_count is len(items); when full list, count gaps among all instances.
    if not gap_only:
        gap_count = sum(1 for row in items if row["gap_kind"] != "covered")

    truncated = False
    if len(items) > limit:
        items = items[:limit]
        truncated = True

    return {
        "as_of": datetime.now(UTC).isoformat(),
        "total_instances": len(instances),
        "gap_count": gap_count if not gap_only else len(items),
        "cross_app_policy_count": cross_app_enabled,
        "truncated": truncated,
        "items": items,
    }


def detection_gap_count(db: Session, org_id: uuid.UUID) -> int:
    """Dashboard rollup: application instances with no_policies or never_matched."""
    report = detection_coverage_report(db, org_id, gap_only=True, limit=EXPORT_MAX)
    return int(report["gap_count"])
