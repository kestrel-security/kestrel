# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Diff desired manifest against live org DB state (CI-safe plan)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import Connector, ConnectorInstance, ConnectorSecret
from kestrel.db.models.finding import Exception_
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
from kestrel.gitops.manifest import DesiredState, GitOpsError, PackSpec
from kestrel.policies.loader import load_policy_directory
from kestrel.policies.packs import PackManifest, resolve_pack_dir

ChangeAction = Literal["create", "update", "noop"]
ResourceKind = Literal["pack", "policy", "connector", "exception"]


@dataclass(frozen=True)
class PlanChange:
    kind: ResourceKind
    identity: str
    action: ChangeAction
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identity": self.identity,
            "action": self.action,
            "details": self.details,
        }


@dataclass
class PlanResult:
    """Result of comparing a DesiredState to the database."""

    changes: list[PlanChange] = field(default_factory=list)
    unmanaged: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return any(c.action != "noop" for c in self.changes) or bool(self.errors)

    @property
    def exit_code(self) -> int:
        """0 when in sync; 1 on drift or plan errors (CI-safe)."""
        return 1 if self.has_drift else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "in_sync": not self.has_drift,
            "changes": [c.to_dict() for c in self.changes],
            "unmanaged": list(self.unmanaged),
            "errors": list(self.errors),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def format_human(self) -> str:
        lines: list[str] = []
        if self.errors:
            lines.append("Plan errors:")
            for err in self.errors:
                lines.append(f"  ✗ {err}")
        actionable = [c for c in self.changes if c.action != "noop"]
        if not actionable and not self.errors:
            lines.append("✓ Desired state matches the database (no drift)")
        else:
            lines.append("Drift detected:" if actionable else "No resource changes.")
            for change in self.changes:
                if change.action == "noop":
                    continue
                detail = ""
                if change.details:
                    detail = " — " + ", ".join(f"{k}={v!r}" for k, v in change.details.items())
                symbol = "+" if change.action == "create" else "~"
                lines.append(f"  {symbol} {change.kind} {change.identity} ({change.action}){detail}")
        if self.unmanaged:
            lines.append("Unmanaged (present in DB, not in manifest — not applied/deleted):")
            for item in self.unmanaged:
                lines.append(f"  · {item['kind']} {item['identity']}")
        return "\n".join(lines)


def compute_plan(session: Session, org_id: uuid.UUID, desired: DesiredState) -> PlanResult:
    """Compare filesystem desired state against org-scoped DB rows."""
    result = PlanResult()
    try:
        _plan_packs(session, org_id, desired, result)
        _plan_policies(session, org_id, desired, result)
        _plan_connectors(session, org_id, desired, result)
        _plan_exceptions(session, org_id, desired, result)
    except GitOpsError as exc:
        result.errors.append(str(exc))
    return result


def _plan_packs(session: Session, org_id: uuid.UUID, desired: DesiredState, result: PlanResult) -> None:
    managed_pack_names: set[str] = set()
    for pack in desired.packs:
        pack_dir, pack_name = _resolve_pack(pack, desired.base_dir)
        managed_pack_names.add(pack_name)
        loaded = load_policy_directory(pack_dir / "policies")
        if any(lp.errors for lp in loaded):
            for lp in loaded:
                if lp.errors:
                    result.errors.append(f"pack '{pack_name}' policy '{lp.slug}': {lp.errors}")
            continue

        drift_fields: dict[str, Any] = {}
        for lp in loaded:
            policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == lp.slug)).one_or_none()
            if policy is None:
                drift_fields[lp.slug] = "missing"
                continue
            latest = _latest_version(session, policy)
            if latest is None or latest.source_text != lp.source_text:
                drift_fields[lp.slug] = "source_changed"
            elif policy.pack_name != pack_name or policy.source != PolicySource.PACK:
                drift_fields[lp.slug] = "metadata"

        if drift_fields:
            action: ChangeAction = "create" if all(v == "missing" for v in drift_fields.values()) else "update"
            result.changes.append(
                PlanChange(kind="pack", identity=pack_name, action=action, details={"policies": drift_fields})
            )
        else:
            result.changes.append(PlanChange(kind="pack", identity=pack_name, action="noop"))

    # Unmanaged pack-sourced policies (group by pack_name)
    rows = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.source == PolicySource.PACK)).all()
    for name in sorted({p.pack_name for p in rows if p.pack_name and p.pack_name not in managed_pack_names}):
        result.unmanaged.append({"kind": "pack", "identity": name})


def _plan_policies(session: Session, org_id: uuid.UUID, desired: DesiredState, result: PlanResult) -> None:
    managed_slugs: set[str] = set()
    for spec in desired.policies:
        assert spec.slug is not None
        managed_slugs.add(spec.slug)
        source_text = (desired.base_dir / spec.path).read_text()
        policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == spec.slug)).one_or_none()
        if policy is None:
            result.changes.append(
                PlanChange(kind="policy", identity=spec.slug, action="create", details={"path": spec.path})
            )
            continue
        if policy.source == PolicySource.SYSTEM:
            result.errors.append(f"policy '{spec.slug}' collides with a system policy")
            continue
        latest = _latest_version(session, policy)
        details: dict[str, Any] = {}
        if latest is None or latest.source_text != source_text:
            details["source"] = "changed"
        if latest is not None and latest.is_enabled != spec.enabled:
            details["enabled"] = {"from": latest.is_enabled, "to": spec.enabled}
        if policy.source == PolicySource.PACK:
            details["note"] = "will convert pack policy to custom on apply"
        if details:
            result.changes.append(PlanChange(kind="policy", identity=spec.slug, action="update", details=details))
        else:
            result.changes.append(PlanChange(kind="policy", identity=spec.slug, action="noop"))

    customs = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.source == PolicySource.CUSTOM)).all()
    for policy in customs:
        if policy.slug not in managed_slugs:
            result.unmanaged.append({"kind": "policy", "identity": policy.slug})


def _plan_connectors(session: Session, org_id: uuid.UUID, desired: DesiredState, result: PlanResult) -> None:
    managed_names: set[str] = set()
    for spec in desired.connectors:
        managed_names.add(spec.name)
        instance, app = _find_connector_by_name(session, org_id, spec.name)
        if instance is None:
            result.changes.append(
                PlanChange(
                    kind="connector",
                    identity=spec.name,
                    action="create",
                    details={"type": spec.type, "schedule_cron": spec.schedule_cron},
                )
            )
            continue

        connector = session.get(Connector, instance.connector_id)
        details: dict[str, Any] = {}
        if connector is None or connector.name != spec.type:
            details["type"] = {"from": connector.name if connector else None, "to": spec.type}
        if app is not None and app.external_tenant_ref != spec.external_tenant_ref:
            details["external_tenant_ref"] = {
                "from": app.external_tenant_ref,
                "to": spec.external_tenant_ref,
            }
        if instance.config != spec.config:
            details["config"] = "changed"
        if instance.auth_method.value != spec.auth_method:
            details["auth_method"] = {"from": instance.auth_method.value, "to": spec.auth_method}
        if instance.sync_mode.value != spec.sync_mode:
            details["sync_mode"] = {"from": instance.sync_mode.value, "to": spec.sync_mode}
        if instance.schedule_cron != spec.schedule_cron:
            details["schedule_cron"] = {"from": instance.schedule_cron, "to": spec.schedule_cron}

        actual_fields = {
            s.field_name
            for s in session.scalars(
                select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id)
            ).all()
        }
        desired_fields = {s.field for s in spec.secrets}
        if desired_fields - actual_fields:
            details["secrets_missing"] = sorted(desired_fields - actual_fields)
        if actual_fields - desired_fields and desired_fields:
            # Only flag extra secrets when the manifest declares a secrets block.
            details["secrets_extra"] = sorted(actual_fields - desired_fields)

        # Missing secrets are informational for apply (secrets are out-of-band)
        # but still count as drift so CI notices incomplete live setups.
        if details:
            result.changes.append(PlanChange(kind="connector", identity=spec.name, action="update", details=details))
        else:
            result.changes.append(PlanChange(kind="connector", identity=spec.name, action="noop"))

    instances = session.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all()
    for instance in instances:
        app = session.get(ApplicationInstance, instance.application_instance_id)
        name = app.display_name if app else str(instance.id)
        if name not in managed_names:
            result.unmanaged.append({"kind": "connector", "identity": name})


def _plan_exceptions(session: Session, org_id: uuid.UUID, desired: DesiredState, result: PlanResult) -> None:
    managed: set[tuple[str, str]] = set()
    for spec in desired.exceptions:
        managed.add((spec.policy, spec.reason))
        policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == spec.policy)).one_or_none()
        if policy is None:
            # May be created by a pack apply in the same run — still report create.
            result.changes.append(
                PlanChange(
                    kind="exception",
                    identity=f"{spec.policy}:{spec.reason}",
                    action="create",
                    details={"policy_missing": True},
                )
            )
            continue

        existing = _find_policy_exception(session, org_id, policy.id, spec.reason)
        if existing is None:
            result.changes.append(
                PlanChange(
                    kind="exception",
                    identity=f"{spec.policy}:{spec.reason}",
                    action="create",
                )
            )
            continue

        desired_exp = _parse_expires(spec.expires_at)
        actual_exp = existing.expires_at
        if _normalize_dt(actual_exp) != _normalize_dt(desired_exp):
            result.changes.append(
                PlanChange(
                    kind="exception",
                    identity=f"{spec.policy}:{spec.reason}",
                    action="update",
                    details={"expires_at": {"from": _fmt_dt(actual_exp), "to": spec.expires_at}},
                )
            )
        else:
            result.changes.append(PlanChange(kind="exception", identity=f"{spec.policy}:{spec.reason}", action="noop"))

    rows = session.scalars(
        select(Exception_).where(
            Exception_.org_id == org_id,
            Exception_.finding_id.is_(None),
            Exception_.policy_id.is_not(None),
        )
    ).all()
    for row in rows:
        policy = session.get(Policy, row.policy_id) if row.policy_id else None
        slug = policy.slug if policy else str(row.policy_id)
        if (slug, row.reason) not in managed:
            result.unmanaged.append({"kind": "exception", "identity": f"{slug}:{row.reason}"})


def _resolve_pack(pack: PackSpec, base_dir: Path) -> tuple[Path, str]:
    if pack.path:
        pack_dir = (base_dir / pack.path).resolve()
        if not (pack_dir / "pack.yaml").is_file():
            raise GitOpsError(f"Pack path '{pack.path}' has no pack.yaml")
        manifest = PackManifest.from_yaml(pack_dir / "pack.yaml")
        if pack.id and pack.id != manifest.name:
            raise GitOpsError(f"Pack id '{pack.id}' does not match pack.yaml name '{manifest.name}'")
        return pack_dir, manifest.name

    assert pack.id is not None
    pack_dir_opt = resolve_pack_dir(pack.id)
    if pack_dir_opt is None:
        raise GitOpsError(f"Pack id '{pack.id}' not found in catalog (KESTREL_PACKS_DIR / ./packs)")
    return pack_dir_opt, pack.id


def _latest_version(session: Session, policy: Policy) -> PolicyVersion | None:
    if policy.current_version_id is not None:
        version = session.get(PolicyVersion, policy.current_version_id)
        if version is not None:
            return version
    return session.scalars(
        select(PolicyVersion).where(PolicyVersion.policy_id == policy.id).order_by(PolicyVersion.version.desc()).limit(1)
    ).first()


def _find_connector_by_name(
    session: Session, org_id: uuid.UUID, name: str
) -> tuple[ConnectorInstance | None, ApplicationInstance | None]:
    apps = session.scalars(
        select(ApplicationInstance).where(
            ApplicationInstance.org_id == org_id,
            ApplicationInstance.display_name == name,
        )
    ).all()
    if not apps:
        return None, None
    app = apps[0]
    instance = session.scalars(
        select(ConnectorInstance).where(
            ConnectorInstance.org_id == org_id,
            ConnectorInstance.application_instance_id == app.id,
        )
    ).first()
    return instance, app


def _find_policy_exception(session: Session, org_id: uuid.UUID, policy_id: uuid.UUID, reason: str) -> Exception_ | None:
    return session.scalars(
        select(Exception_).where(
            Exception_.org_id == org_id,
            Exception_.policy_id == policy_id,
            Exception_.finding_id.is_(None),
            Exception_.reason == reason,
        )
    ).one_or_none()


def _parse_expires(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _normalize_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat()


def _fmt_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()
