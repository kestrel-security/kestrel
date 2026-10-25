# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Kestrel Pack manifest (pack.yaml) loading and installation: upserts a
pack's policies into the Policy/PolicyVersion tables for an org.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.compliance import ComplianceControl, ComplianceFramework, MappingSource, PolicyControlMapping
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.findings.lifecycle import repoint_findings_to_current_version, resolve_findings_for_disabled_policy
from kestrel.policies.loader import LoadedPolicy, load_policy_directory

VALID_APPLICATIONS = frozenset(
    {
        "github",
        "okta",
        "google_workspace",
        "slack",
        "cross_app",
        "custom",
    }
)

_LOG = logging.getLogger(__name__)


@dataclass
class PackManifest:
    name: str
    version: str
    description: str
    policy_slugs: list[str]
    display_name: str = ""
    summary: str = ""
    application: str | None = None
    categories: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    vendor_baselines: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PackManifest:
        data = yaml.safe_load(Path(path).read_text())
        application = data.get("application")
        if application is not None and application not in VALID_APPLICATIONS:
            raise ValueError(
                f"Invalid application {application!r} in {path} (allowed: {', '.join(sorted(VALID_APPLICATIONS))})"
            )
        return cls(
            name=data["name"],
            version=data["version"],
            description=data.get("description", ""),
            policy_slugs=list(data.get("policies") or []),
            display_name=str(data.get("display_name") or data["name"]),
            summary=str(data.get("summary") or "").strip(),
            application=application,
            categories=[str(c) for c in (data.get("categories") or [])],
            frameworks=[str(f) for f in (data.get("frameworks") or [])],
            vendor_baselines=[str(v) for v in (data.get("vendor_baselines") or [])],
        )


@dataclass(frozen=True)
class AvailablePack:
    """A pack discovered on disk under the catalog root (see `get_packs_dir`)."""

    name: str
    version: str
    description: str
    policy_count: int
    policy_slugs: tuple[str, ...]
    path: Path
    display_name: str = ""
    summary: str = ""
    application: str | None = None
    categories: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    vendor_baselines: tuple[str, ...] = ()


def get_packs_dir() -> Path:
    """Catalog root for discoverable packs.

    Override with `KESTREL_PACKS_DIR`. Default is `./packs` relative to the
    process cwd (repo root in local/dev; set explicitly in container images).
    """
    from kestrel.env import getenv

    override = getenv("KESTREL_PACKS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / "packs").resolve()


def list_available_packs(packs_dir: str | Path | None = None) -> list[AvailablePack]:
    """Lists immediate child directories that contain a valid `pack.yaml`."""
    root = Path(packs_dir) if packs_dir is not None else get_packs_dir()
    if not root.is_dir():
        return []

    found: list[AvailablePack] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        manifest_path = child / "pack.yaml"
        if not manifest_path.is_file():
            continue
        try:
            manifest = PackManifest.from_yaml(manifest_path)
        except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
            _LOG.warning("skipping pack with an invalid manifest: %s", manifest_path, exc_info=True)
            continue
        found.append(
            AvailablePack(
                name=manifest.name,
                version=manifest.version,
                description=manifest.description.strip(),
                policy_count=len(manifest.policy_slugs),
                policy_slugs=tuple(manifest.policy_slugs),
                path=child.resolve(),
                display_name=manifest.display_name,
                summary=manifest.summary,
                application=manifest.application,
                categories=tuple(manifest.categories),
                frameworks=tuple(manifest.frameworks),
                vendor_baselines=tuple(manifest.vendor_baselines),
            )
        )
    return found


def resolve_pack_dir(name: str, packs_dir: str | Path | None = None) -> Path | None:
    """Resolves a catalog pack by manifest `name` (not necessarily directory name)."""
    for pack in list_available_packs(packs_dir):
        if pack.name == name:
            return pack.path
    return None


def resolve_pack_fixture_path(
    pack_name: str,
    policy_slug: str,
    packs_dir: str | Path | None = None,
) -> Path | None:
    """Locate ``policies/fixtures/{slug}.fixtures.json`` for a pack policy.

    Only the named pack is searched: a pack owns the fixtures for its own
    policies, so a fixture found in some other pack would be testing a policy
    against data that pack's author never wrote for it.
    """
    pack_dir = resolve_pack_dir(pack_name, packs_dir)
    if pack_dir is None:
        return None
    fixtures_dir = pack_dir / "policies" / "fixtures"
    for path in (
        fixtures_dir / f"{policy_slug}.fixtures.json",
        fixtures_dir / f"{policy_slug.replace('-', '_')}.fixtures.json",
    ):
        if path.is_file():
            return path.resolve()
    return None


def load_pack_fixture(
    pack_name: str,
    policy_slug: str,
    packs_dir: str | Path | None = None,
) -> dict | None:
    """Load pack fixture JSON for ``policy_slug``, or ``None`` if missing."""
    path = resolve_pack_fixture_path(pack_name, policy_slug, packs_dir)
    if path is None:
        return None
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        return None
    return data


def pack_catalog_detail(name: str, packs_dir: str | Path | None = None) -> dict | None:
    """Marketplace detail: manifest + policy titles from on-disk .py files."""
    pack = next(
        (p for p in list_available_packs(packs_dir) if p.name == name),
        None,
    )
    if pack is None:
        return None
    loaded = load_policy_directory(pack.path / "policies")
    by_slug = {lp.slug: lp for lp in loaded}
    policies: list[dict[str, Any]] = []
    for slug in pack.policy_slugs:
        lp = by_slug.get(slug)
        if lp is None or lp.compiled is None:
            policies.append(
                {
                    "slug": slug,
                    "title": slug,
                    "severity": None,
                    "description": None,
                    "present": False,
                    "resource_type": None,
                    "category": None,
                }
            )
            continue
        contract = lp.compiled.contract
        resource_type = getattr(contract, "resource_type", None) or "identity"
        policies.append(
            {
                "slug": slug,
                "title": contract.title,
                "severity": contract.severity,
                "description": contract.description,
                "present": True,
                "resource_type": resource_type,
                "category": _category_for_resource_type(resource_type),
                "profile": contract.profile,
                "requires": list(contract.requires),
            }
        )
    return {
        "name": pack.name,
        "version": pack.version,
        "description": pack.description,
        "policy_count": pack.policy_count,
        "policy_slugs": list(pack.policy_slugs),
        "policies": policies,
        "display_name": pack.display_name,
        "summary": pack.summary,
        "application": pack.application,
        "categories": list(pack.categories),
        "frameworks": list(pack.frameworks),
        "vendor_baselines": list(pack.vendor_baselines),
    }


def _category_for_resource_type(resource_type: str) -> str:
    return {
        "identity": "Identity",
        "grant": "Privileged access",
        "tenant_setting": "Tenant settings",
        "resource": "Repository",
        "application": "OAuth / apps",
        "oauth_application": "OAuth / apps",
        "event": "Activity",
    }.get(resource_type, "Other")


@dataclass
class PackInstallPreview:
    """Diff of on-disk pack policies vs org-installed rows (by slug)."""

    pack_name: str
    pack_version: str
    installed: bool
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    unassessable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.pack_name,
            "version": self.pack_version,
            "installed": self.installed,
            "added": list(self.added),
            "updated": list(self.updated),
            "unchanged": list(self.unchanged),
            "unassessable": list(self.unassessable),
            "counts": {
                "added": len(self.added),
                "updated": len(self.updated),
                "unchanged": len(self.unchanged),
                "unassessable": len(self.unassessable),
            },
        }


def preview_pack_install(
    session: Session,
    org_id: uuid.UUID,
    pack_dir: str | Path,
    *,
    profile: str | None = None,
) -> PackInstallPreview:
    """Compare on-disk pack policies to org-installed policies by slug.

    Classification:
    - added: slug not present for the org
    - updated: source text, severity, or title differs from the current version
    - unchanged: source, severity, and title match
    """
    pack_dir = Path(pack_dir)
    manifest = PackManifest.from_yaml(pack_dir / "pack.yaml")

    loaded = load_policy_directory(pack_dir / "policies")

    coverage = None
    try:
        from kestrel.policies.coverage import compute_pack_coverage

        coverage = compute_pack_coverage(session, org_id, pack_dir)
    except (OSError, ValueError, yaml.YAMLError):
        # An unreadable or invalid connector manifest; the preview is still
        # useful without the coverage column.
        _LOG.warning("pack coverage unavailable for %s", manifest.name, exc_info=True)
        coverage = None

    installed_pack = session.scalars(
        select(Policy.id).where(Policy.org_id == org_id, Policy.pack_name == manifest.name).limit(1)
    ).first()

    preview = PackInstallPreview(
        pack_name=manifest.name,
        pack_version=manifest.version,
        installed=installed_pack is not None,
    )

    for lp in loaded:
        if lp.errors or lp.compiled is None:
            raise ValueError(f"Cannot preview invalid policy '{lp.slug}': {lp.errors}")

        contract = lp.compiled.contract
        slug = contract.policy_id

        if profile is not None and contract.profile != profile:
            continue

        if coverage is not None:
            cov_row = next((p for p in coverage.policies if p.slug == slug), None)
            if cov_row is not None and cov_row.status == "not_assessable":
                preview.unassessable.append(slug)

        policy = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.slug == slug)).one_or_none()

        if policy is None:
            preview.added.append(slug)
            continue

        version = session.get(PolicyVersion, policy.current_version_id) if policy.current_version_id else None
        if version is None:
            preview.added.append(slug)
            continue

        source_changed = version.source_text != lp.source_text
        severity_changed = version.severity.value != contract.severity
        title_changed = policy.title != contract.title
        if source_changed or severity_changed or title_changed:
            preview.updated.append(slug)
        else:
            preview.unchanged.append(slug)

    preview.added.sort()
    preview.updated.sort()
    preview.unchanged.sort()
    preview.unassessable.sort()
    return preview


@dataclass
class PackValidationResult:
    pack_name: str
    loaded_policies: list[LoadedPolicy] = field(default_factory=list)

    @property
    def errors(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for lp in self.loaded_policies:
            if lp.errors:
                out[lp.slug] = lp.errors
        return out

    @property
    def is_valid(self) -> bool:
        return not self.errors


def validate_pack(pack_dir: str | Path) -> PackValidationResult:
    pack_dir = Path(pack_dir)
    manifest = PackManifest.from_yaml(pack_dir / "pack.yaml")
    loaded = load_policy_directory(pack_dir / "policies")
    result = PackValidationResult(pack_name=manifest.name, loaded_policies=loaded)

    loaded_names = {lp.slug for lp in loaded}
    for slug in set(manifest.policy_slugs) - loaded_names:
        result.loaded_policies.append(
            LoadedPolicy(
                path=pack_dir / "policies" / f"{slug.replace('-', '_')}.py",
                source_text="",
                compiled=None,
                errors=[f"policy '{slug}' listed in pack.yaml but no matching .py file was found"],
            )
        )
    return result


def install_pack(
    session: Session,
    org_id: uuid.UUID,
    pack_dir: str | Path,
    *,
    profile: str | None = None,
) -> list[Policy]:
    """Upserts every policy in a pack into Policy/PolicyVersion for an org.

    Re-installing keeps the operator's enable/disable choice for each policy,
    never adopts a custom policy that happens to share a slug, and retires
    (disables) policies this pack installed earlier but no longer ships.
    """
    pack_dir = Path(pack_dir)
    manifest = PackManifest.from_yaml(pack_dir / "pack.yaml")

    loaded = load_policy_directory(pack_dir / "policies")
    controls_by_key = _install_compliance_controls(session, pack_dir)

    installed = []
    for lp in loaded:
        if lp.errors or lp.compiled is None:
            raise ValueError(f"Cannot install invalid policy '{lp.slug}': {lp.errors}")

        contract = lp.compiled.contract
        if profile is not None and contract.profile != profile:
            continue
        compliance_mappings = dict(contract.compliance)

        existing = session.scalars(
            select(Policy).where(Policy.org_id == org_id, Policy.slug == contract.policy_id)
        ).one_or_none()

        if existing is not None and existing.source != PolicySource.PACK:
            raise ValueError(
                f"Cannot install '{contract.policy_id}' from pack '{manifest.name}': a "
                f"{existing.source.value} policy with that slug already exists in this organization"
            )

        if existing is None:
            policy = Policy(
                id=uuid.uuid4(),
                org_id=org_id,
                slug=contract.policy_id,
                title=contract.title,
                description=contract.description or None,
                source=PolicySource.PACK,
                pack_name=manifest.name,
            )
            session.add(policy)
            session.flush()
            version_number = 1
            keep_enabled = True
        else:
            policy = existing
            latest_version = session.scalars(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy.id)
                .order_by(PolicyVersion.version.desc())
                .limit(1)
            ).first()
            # Keep pack_name aligned with the owning leaf pack on re-install.
            policy.pack_name = manifest.name
            if latest_version is not None and latest_version.source_text == lp.source_text:
                _sync_policy_control_mappings(session, policy, compliance_mappings, controls_by_key)
                installed.append(policy)
                continue
            version_number = (latest_version.version + 1) if latest_version else 1
            # A pack upgrade is not a reason to re-enable a policy the operator
            # turned off; their choice travels to the new version.
            keep_enabled = latest_version.is_enabled if latest_version is not None else True
            policy.title = contract.title
            policy.description = contract.description or None

        version = PolicyVersion(
            id=uuid.uuid4(),
            policy_id=policy.id,
            version=version_number,
            source_text=lp.source_text,
            severity=Severity(contract.severity),
            remediation=contract.remediation,
            compliance_mappings=compliance_mappings or None,
            is_enabled=keep_enabled,
            created_by="kestrel pack install",
        )
        session.add(version)
        session.flush()
        policy.current_version_id = version.id
        # Findings are keyed by policy: keep the open ones on the new version.
        repoint_findings_to_current_version(session, policy)
        _sync_policy_control_mappings(session, policy, compliance_mappings, controls_by_key)
        installed.append(policy)

    _retire_removed_pack_policies(
        session, org_id, manifest.name, {lp.compiled.contract.policy_id for lp in loaded if lp.compiled}
    )
    return installed


def _retire_removed_pack_policies(session: Session, org_id: uuid.UUID, pack_name: str, shipped_slugs: set[str]) -> int:
    """Disable policies this pack installed before but no longer contains.

    Compared against every policy the pack ships, not only the profile being
    installed, so installing one profile never retires another's. Rows are
    kept (findings and history point at them); only evaluation stops.
    """
    orphaned = session.scalars(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.source == PolicySource.PACK,
            Policy.pack_name == pack_name,
            Policy.slug.not_in(shipped_slugs),
        )
    ).all()
    retired = _disable_current_versions(session, orphaned)
    if retired:
        _LOG.info("pack %s: retired %d polic%s no longer shipped", pack_name, retired, "y" if retired == 1 else "ies")
    return retired


def retire_missing_packs(session: Session, org_id: uuid.UUID, packs_dir: str | Path | None = None) -> int:
    """Disable pack policies whose whole pack is no longer in the catalog.

    `install_pack` retires slugs a pack dropped, but a pack that was removed
    entirely is never installed again, so nothing visits its policies. Rows
    are kept, as there. Only for an org whose packs all come from this
    catalog: a pack installed from another path would be retired too.
    """
    shipped = {pack.name for pack in list_available_packs(packs_dir)}
    orphaned = session.scalars(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.source == PolicySource.PACK,
            Policy.pack_name.is_not(None),
            Policy.pack_name.not_in(shipped),
        )
    ).all()
    retired = _disable_current_versions(session, orphaned)
    if retired:
        names = sorted({str(policy.pack_name) for policy in orphaned})
        _LOG.info("retired %d polic%s from removed packs: %s", retired, "y" if retired == 1 else "ies", ", ".join(names))
    return retired


def _disable_current_versions(session: Session, policies: Sequence[Policy]) -> int:
    retired = 0
    for policy in policies:
        if policy.current_version_id is None:
            continue
        version = session.get(PolicyVersion, policy.current_version_id)
        if version is not None and version.is_enabled:
            version.is_enabled = False
            retired += 1
    session.flush()
    return retired


def _install_compliance_controls(session: Session, pack_dir: Path) -> dict[tuple[str, str], ComplianceControl]:
    controls_path = pack_dir / "compliance_controls.yaml"
    by_key: dict[tuple[str, str], ComplianceControl] = {}
    if not controls_path.exists():
        return by_key

    data = yaml.safe_load(controls_path.read_text())
    for entry in data.get("controls", []):
        framework = ComplianceFramework(entry["framework"])
        control_id = str(entry["control_id"])
        control = session.scalars(
            select(ComplianceControl).where(
                ComplianceControl.org_id.is_(None),
                ComplianceControl.framework == framework,
                ComplianceControl.control_id == control_id,
            )
        ).one_or_none()
        if control is None:
            control = ComplianceControl(
                id=uuid.uuid4(),
                org_id=None,
                framework=framework,
                control_id=control_id,
                title=entry["title"],
                description=entry.get("description"),
            )
            session.add(control)
            session.flush()
        by_key[(framework.value, control_id)] = control

    return by_key


def _resolve_control(
    session: Session,
    controls_by_key: dict[tuple[str, str], ComplianceControl],
    framework: str,
    control_id: str,
) -> ComplianceControl | None:
    """The control for one claimed mapping, from this pack's catalog or another's.

    Compliance controls are installed shared (`org_id = null`), so a policy may
    legitimately map to a control a different pack defines -- `cross-app` maps
    to the internal control GH-01, which lives in `github-posture`. Looking only in the current
    pack's catalog dropped those mappings silently: the policy installed with no
    compliance coverage and nothing said so.
    """
    key = (framework, control_id)
    cached = controls_by_key.get(key)
    if cached is not None:
        return cached
    try:
        framework_enum = ComplianceFramework(framework)
    except ValueError:
        return None
    control = session.scalars(
        select(ComplianceControl).where(
            ComplianceControl.org_id.is_(None),
            ComplianceControl.framework == framework_enum,
            ComplianceControl.control_id == control_id,
        )
    ).one_or_none()
    if control is not None:
        controls_by_key[key] = control
    return control


def _sync_policy_control_mappings(
    session: Session,
    policy: Policy,
    compliance_mappings: dict[str, list[str]],
    controls_by_key: dict[tuple[str, str], ComplianceControl],
) -> None:
    for framework, control_ids in compliance_mappings.items():
        for control_id in control_ids:
            control = _resolve_control(session, controls_by_key, framework, str(control_id))
            if control is None:
                # A control no pack defines. The policy still installs; it just
                # carries no compliance coverage. `tests/unit/packs` fails on
                # this at authoring time so it cannot reach an operator.
                continue
            existing = session.scalars(
                select(PolicyControlMapping).where(
                    PolicyControlMapping.policy_id == policy.id,
                    PolicyControlMapping.compliance_control_id == control.id,
                )
            ).one_or_none()
            if existing is None:
                session.add(
                    PolicyControlMapping(
                        id=uuid.uuid4(),
                        policy_id=policy.id,
                        compliance_control_id=control.id,
                        source=MappingSource.PACK_DEFAULT,
                    )
                )
                session.flush()


def set_pack_enabled(
    session: Session,
    org_id: uuid.UUID,
    pack_name: str,
    *,
    enabled: bool,
    actor_operator_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> int:
    """Bulk enable or disable all policies installed from ``pack_name``.

    Disabling resolves each policy's open findings (reason
    ``policy_disabled``), as ``set_current_version_enabled`` does.

    Returns the number of policy versions updated.
    """
    policies = session.scalars(select(Policy).where(Policy.org_id == org_id, Policy.pack_name == pack_name)).all()
    updated = 0
    for policy in policies:
        if policy.current_version_id is None:
            continue
        version = session.get(PolicyVersion, policy.current_version_id)
        if version is None or version.is_enabled == enabled:
            continue
        version.is_enabled = enabled
        updated += 1
        if not enabled:
            resolve_findings_for_disabled_policy(
                session,
                policy,
                actor_operator_id=actor_operator_id,
                webhook_delivery_ids=webhook_delivery_ids,
            )
    session.flush()
    return updated


def enable_pack(session: Session, org_id: uuid.UUID, pack_name: str) -> int:
    return set_pack_enabled(session, org_id, pack_name, enabled=True)


def disable_pack(
    session: Session,
    org_id: uuid.UUID,
    pack_name: str,
    *,
    actor_operator_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> int:
    return set_pack_enabled(
        session,
        org_id,
        pack_name,
        enabled=False,
        actor_operator_id=actor_operator_id,
        webhook_delivery_ids=webhook_delivery_ids,
    )
