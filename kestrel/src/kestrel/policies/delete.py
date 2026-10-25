# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Permanently delete a policy and everything derived from it.

Disable is the reversible path (``authoring.set_current_version_enabled``);
this is the irreversible one. Findings reference policy versions and
evaluations NOT NULL, so a policy cannot be removed while its history stays:
versions, evaluations, findings and their dependents, control mappings and
org-wide exceptions all go with it.

System policies are refused: they are owned by the product, not the operator.
Pack policies are allowed; reinstalling the pack upserts by slug and brings
the policy back (without its findings), which the UI says before confirming.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kestrel.db.locks import POLICY_EVALUATION, org_advisory_xact_lock
from kestrel.db.models.compliance import PolicyControlMapping
from kestrel.db.models.finding import Exception_, Finding
from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicySource, PolicyVersion
from kestrel.findings.purge import purge_findings


class PolicyDeleteError(ValueError):
    """The policy cannot be deleted; the message says why."""


class SystemPolicyDeleteError(PolicyDeleteError):
    """System policies are product-owned and can only be disabled."""


def delete_policy(session: Session, *, policy: Policy) -> dict[str, Any]:
    """Delete ``policy`` and its versions, evaluations, findings, mappings and exceptions.

    The caller has already scoped the lookup to the organization. Runs inside
    the caller's transaction and does not commit. Returns a summary of what
    was removed, for the audit log.
    """
    if policy.source == PolicySource.SYSTEM:
        raise SystemPolicyDeleteError("system policies cannot be deleted; disable it instead")

    # Serialised with evaluation before any write, like enable/disable: an
    # evaluation that commits mid-delete would insert findings for a version
    # that is about to go.
    org_advisory_xact_lock(session, policy.org_id, POLICY_EVALUATION)

    version_ids = list(session.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == policy.id)).all())
    evaluation_ids: list = []
    finding_ids: set = set()
    if version_ids:
        evaluation_ids = list(
            session.scalars(select(PolicyEvaluation.id).where(PolicyEvaluation.policy_version_id.in_(version_ids))).all()
        )
        finding_ids.update(session.scalars(select(Finding.id).where(Finding.policy_version_id.in_(version_ids))).all())
    if evaluation_ids:
        finding_ids.update(session.scalars(select(Finding.id).where(Finding.policy_evaluation_id.in_(evaluation_ids))).all())

    findings_deleted = purge_findings(session, list(finding_ids))
    if evaluation_ids:
        session.execute(delete(PolicyEvaluation).where(PolicyEvaluation.id.in_(evaluation_ids)))
    mappings = session.execute(delete(PolicyControlMapping).where(PolicyControlMapping.policy_id == policy.id))
    # Org-wide exceptions for this policy (finding-scoped ones went with the
    # findings). An exception for a policy that no longer exists is dead data.
    exceptions = session.execute(delete(Exception_).where(Exception_.policy_id == policy.id))
    if version_ids:
        session.execute(delete(PolicyVersion).where(PolicyVersion.id.in_(version_ids)))

    summary = {
        "slug": policy.slug,
        "source": policy.source.value if isinstance(policy.source, PolicySource) else str(policy.source),
        "pack_name": policy.pack_name,
        "versions_deleted": len(version_ids),
        "evaluations_deleted": len(evaluation_ids),
        "findings_deleted": findings_deleted,
        "control_mappings_deleted": int(getattr(mappings, "rowcount", 0) or 0),
        "exceptions_deleted": int(getattr(exceptions, "rowcount", 0) or 0),
    }
    session.delete(policy)
    session.flush()
    return summary
