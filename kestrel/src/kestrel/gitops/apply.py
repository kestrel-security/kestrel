# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Apply a GitOps desired-state plan idempotently."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.connectors.authoring import ConnectorAuthoringError, create_connector_instance
from kestrel.db.models.connector import AuthMethod, Connector, SyncMode
from kestrel.db.models.finding import Exception_
from kestrel.db.models.policy import Policy, PolicySource
from kestrel.gitops.diff import PlanResult, _find_connector_by_name, _find_policy_exception, _resolve_pack, compute_plan
from kestrel.gitops.manifest import DesiredState, GitOpsError
from kestrel.policies.authoring import (
    PolicyAuthoringError,
    create_custom_policy,
    publish_new_version,
    set_current_version_enabled,
)
from kestrel.policies.packs import install_pack
from kestrel.scheduling.cron import InvalidCronError, validate_cron
from kestrel.secrets.store import delete_secrets
from kestrel.security.ssrf import UnsafeConnectorURLError, changed_endpoint_fields, validate_connector_config_urls


@dataclass
class ApplyResult:
    applied: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "applied": list(self.applied),
            "skipped": list(self.skipped),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def apply_manifest(
    session: Session,
    org_id: uuid.UUID,
    desired: DesiredState,
    *,
    dry_run: bool = False,
) -> ApplyResult:
    """Idempotently apply desired state. Never writes connector secrets."""
    plan = compute_plan(session, org_id, desired)
    result = ApplyResult()
    if plan.errors:
        result.errors.extend(plan.errors)
        return result

    if dry_run:
        for change in plan.changes:
            if change.action == "noop":
                result.skipped.append(change.to_dict())
            else:
                result.applied.append({**change.to_dict(), "dry_run": True})
        return result

    try:
        _apply_packs(session, org_id, desired, plan, result)
        _apply_policies(session, org_id, desired, plan, result)
        _apply_connectors(session, org_id, desired, plan, result)
        _apply_exceptions(session, org_id, desired, plan, result)
    except (GitOpsError, PolicyAuthoringError, ConnectorAuthoringError, ValueError) as exc:
        result.errors.append(str(exc))

    return result


def _apply_packs(
    session: Session,
    org_id: uuid.UUID,
    desired: DesiredState,
    plan: PlanResult,
    result: ApplyResult,
) -> None:
    needed = {c.identity for c in plan.changes if c.kind == "pack" and c.action != "noop"}
    for pack in desired.packs:
        pack_dir, pack_name = _resolve_pack(pack, desired.base_dir)
        if pack_name not in needed:
            result.skipped.append({"kind": "pack", "identity": pack_name, "action": "noop"})
            continue
        installed = install_pack(session, org_id, pack_dir)
        result.applied.append(
            {
                "kind": "pack",
                "identity": pack_name,
                "action": "update",
                "policies": [p.slug for p in installed],
            }
        )


def _apply_policies(
    session: Session,
    org_id: uuid.UUID,
    desired: DesiredState,
    plan: PlanResult,
    result: ApplyResult,
) -> None:
    needed = {c.identity: c for c in plan.changes if c.kind == "policy"}
    for spec in desired.policies:
        assert spec.slug is not None
        change = needed.get(spec.slug)
        if change is None or change.action == "noop":
            result.skipped.append({"kind": "policy", "identity": spec.slug, "action": "noop"})
            continue

        source_text = (desired.base_dir / spec.path).read_text()
        policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == spec.slug)).one_or_none()

        if policy is None:
            policy = create_custom_policy(session, org_id=org_id, source_text=source_text, created_by="kestrel apply")
            set_current_version_enabled(session, policy=policy, is_enabled=spec.enabled)
            result.applied.append({"kind": "policy", "identity": spec.slug, "action": "create"})
            continue

        if policy.source == PolicySource.SYSTEM:
            result.errors.append(f"cannot apply over system policy '{spec.slug}'")
            continue

        if policy.source == PolicySource.PACK:
            # Custom GitOps path takes ownership of this slug.
            policy.source = PolicySource.CUSTOM
            policy.pack_name = None

        publish_new_version(session, policy=policy, source_text=source_text, created_by="kestrel apply")
        set_current_version_enabled(session, policy=policy, is_enabled=spec.enabled)
        result.applied.append({"kind": "policy", "identity": spec.slug, "action": "update"})


def _apply_connectors(
    session: Session,
    org_id: uuid.UUID,
    desired: DesiredState,
    plan: PlanResult,
    result: ApplyResult,
) -> None:
    needed = {c.identity: c for c in plan.changes if c.kind == "connector"}
    for spec in desired.connectors:
        change = needed.get(spec.name)
        if change is None or change.action == "noop":
            result.skipped.append({"kind": "connector", "identity": spec.name, "action": "noop"})
            continue

        try:
            validate_connector_config_urls(spec.config, require_https=spec.sync_mode != SyncMode.FIXTURES.value)
        except UnsafeConnectorURLError as exc:
            result.errors.append(f"connector '{spec.name}': {exc}")
            continue

        if spec.schedule_cron is not None:
            try:
                validate_cron(spec.schedule_cron)
            except InvalidCronError as exc:
                result.errors.append(f"connector '{spec.name}': {exc}")
                continue

        instance, app = _find_connector_by_name(session, org_id, spec.name)
        if instance is None:
            try:
                instance = create_connector_instance(
                    session,
                    org_id=org_id,
                    connector_name=spec.type,
                    display_name=spec.name,
                    external_tenant_ref=spec.external_tenant_ref,
                    config=spec.config,
                    auth_method=spec.auth_method,
                    sync_mode=spec.sync_mode,
                    schedule_cron=spec.schedule_cron,
                )
            except ConnectorAuthoringError as exc:
                result.errors.append(f"connector '{spec.name}': {exc}")
                continue
            if spec.secrets:
                fields = ", ".join(s.field for s in spec.secrets)
                result.warnings.append(
                    f"connector '{spec.name}' created without secrets "
                    f"(set out-of-band: {fields}; refs={', '.join(s.ref for s in spec.secrets)})"
                )
            result.applied.append({"kind": "connector", "identity": spec.name, "action": "create"})
            continue

        # Update non-secret fields only.
        connector = session.get(Connector, instance.connector_id)
        if connector is not None and connector.name != spec.type:
            result.errors.append(
                f"connector '{spec.name}' type mismatch (db={connector.name}, desired={spec.type}); recreate manually"
            )
            continue

        # Same rule as PATCH /connector-instances/{id}: credentials never
        # follow a connector to a new host.
        endpoint_changes = changed_endpoint_fields(instance.config, spec.config)
        instance.config = dict(spec.config)
        if endpoint_changes:
            cleared = delete_secrets(session, connector_instance_id=instance.id)
            if cleared:
                result.warnings.append(
                    f"connector '{spec.name}': {', '.join(endpoint_changes)} changed, so its stored secrets "
                    f"({', '.join(cleared)}) were cleared; set them again via API/UI"
                )
        try:
            instance.auth_method = AuthMethod(spec.auth_method)
            instance.sync_mode = SyncMode(spec.sync_mode)
        except ValueError as exc:
            result.errors.append(f"connector '{spec.name}': {exc}")
            continue
        instance.schedule_cron = spec.schedule_cron
        if app is not None and app.external_tenant_ref != spec.external_tenant_ref:
            app.external_tenant_ref = spec.external_tenant_ref

        if change.details.get("secrets_missing"):
            result.warnings.append(
                f"connector '{spec.name}' still missing secret fields "
                f"{change.details['secrets_missing']} — set via API/UI, never via YAML"
            )

        result.applied.append({"kind": "connector", "identity": spec.name, "action": "update"})


def _apply_exceptions(
    session: Session,
    org_id: uuid.UUID,
    desired: DesiredState,
    plan: PlanResult,
    result: ApplyResult,
) -> None:
    needed = {c.identity: c for c in plan.changes if c.kind == "exception"}
    for spec in desired.exceptions:
        identity = f"{spec.policy}:{spec.reason}"
        change = needed.get(identity)
        if change is None or change.action == "noop":
            result.skipped.append({"kind": "exception", "identity": identity, "action": "noop"})
            continue

        policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == spec.policy)).one_or_none()
        if policy is None:
            result.errors.append(f"exception for unknown policy '{spec.policy}'")
            continue

        expires_at = _parse_expires(spec.expires_at)
        existing = _find_policy_exception(session, org_id, policy.id, spec.reason)
        if existing is None:
            session.add(
                Exception_(
                    id=uuid.uuid4(),
                    org_id=org_id,
                    finding_id=None,
                    policy_id=policy.id,
                    reason=spec.reason,
                    created_by_operator_id=None,
                    expires_at=expires_at,
                )
            )
            session.flush()
            result.applied.append({"kind": "exception", "identity": identity, "action": "create"})
        else:
            existing.expires_at = expires_at
            result.applied.append({"kind": "exception", "identity": identity, "action": "update"})


def _parse_expires(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
