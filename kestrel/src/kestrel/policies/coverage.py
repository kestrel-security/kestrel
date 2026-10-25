# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack coverage: join policy REQUIRES against connector provides_capabilities."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.manifest import ConnectorManifest
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.policies.loader import load_policy_directory
from kestrel.policies.packs import PackManifest, resolve_pack_dir

# Map pack application slug → connector manifest name + ApplicationType
_APP_TO_CONNECTOR: dict[str, tuple[str, ApplicationType]] = {
    "github": ("github", ApplicationType.GITHUB),
    "okta": ("okta", ApplicationType.OKTA),
    "slack": ("slack", ApplicationType.SLACK),
    "google_workspace": ("google_workspace", ApplicationType.GOOGLE_WORKSPACE),
}

_CONNECTORS_ROOT = Path(__file__).resolve().parents[4] / "connectors"


def _connector_manifest_path(name: str) -> Path | None:
    path = _CONNECTORS_ROOT / name / "manifest.yaml"
    return path if path.is_file() else None


def load_connector_capabilities(connector_name: str) -> frozenset[str]:
    path = _connector_manifest_path(connector_name)
    if path is None:
        return frozenset()
    manifest = ConnectorManifest.from_yaml(path)
    return frozenset(manifest.provides_capabilities)


def org_connected_application_types(session: Session, org_id: uuid.UUID) -> set[ApplicationType]:
    rows = session.scalars(
        select(Application.application_type)
        .join(ApplicationInstance, ApplicationInstance.application_id == Application.id)
        .where(ApplicationInstance.org_id == org_id)
    ).all()
    return set(rows)


@dataclass
class PolicyCoverageRow:
    slug: str
    title: str
    profile: str
    requires: tuple[str, ...]
    status: str  # monitored | not_assessable
    reason: str | None = None


@dataclass
class PackCoverage:
    pack_name: str
    pack_version: str
    application: str | None
    connected: bool
    policies: list[PolicyCoverageRow] = field(default_factory=list)

    def to_dict(self) -> dict:
        monitored = [p for p in self.policies if p.status == "monitored"]
        not_assessable = [p for p in self.policies if p.status == "not_assessable"]
        return {
            "name": self.pack_name,
            "version": self.pack_version,
            "application": self.application,
            "connected": self.connected,
            "counts": {
                "monitored": len(monitored),
                "not_assessable": len(not_assessable),
                "total": len(self.policies),
            },
            "policies": [
                {
                    "slug": p.slug,
                    "title": p.title,
                    "profile": p.profile,
                    "requires": list(p.requires),
                    "status": p.status,
                    "reason": p.reason,
                }
                for p in self.policies
            ],
        }


def _assess_policy(
    requires: tuple[str, ...],
    available_capabilities: frozenset[str],
    *,
    connected: bool,
) -> tuple[str, str | None]:
    if not requires:
        return "monitored", None
    if not connected:
        return "not_assessable", "No connected integration for this application"
    missing = [req for req in requires if req not in available_capabilities]
    if missing:
        return "not_assessable", f"Connector does not collect: {', '.join(missing)}"
    return "monitored", None


def compute_pack_coverage(
    session: Session,
    org_id: uuid.UUID,
    pack_dir: str | Path,
) -> PackCoverage:
    pack_dir = Path(pack_dir)
    manifest = PackManifest.from_yaml(pack_dir / "pack.yaml")
    loaded = load_policy_directory(pack_dir / "policies")

    app = manifest.application
    connector_name: str | None = None
    app_type: ApplicationType | None = None
    if app and app in _APP_TO_CONNECTOR:
        connector_name, app_type = _APP_TO_CONNECTOR[app]

    connected_types = org_connected_application_types(session, org_id)
    connected = app_type in connected_types if app_type else False

    capabilities: frozenset[str] = frozenset()
    if connector_name:
        capabilities = load_connector_capabilities(connector_name)

    rows: list[PolicyCoverageRow] = []
    for lp in loaded:
        if lp.compiled is None:
            continue
        contract = lp.compiled.contract
        status, reason = _assess_policy(
            contract.requires,
            capabilities,
            connected=connected,
        )
        rows.append(
            PolicyCoverageRow(
                slug=contract.policy_id,
                title=contract.title,
                profile=contract.profile,
                requires=contract.requires,
                status=status,
                reason=reason,
            )
        )

    return PackCoverage(
        pack_name=manifest.name,
        pack_version=manifest.version,
        application=app,
        connected=connected,
        policies=rows,
    )


def pack_coverage_for_name(session: Session, org_id: uuid.UUID, name: str) -> PackCoverage | None:
    pack_dir = resolve_pack_dir(name)
    if pack_dir is None:
        return None
    return compute_pack_coverage(session, org_id, pack_dir)
