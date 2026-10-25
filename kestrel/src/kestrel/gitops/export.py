# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Export live org state to a GitOps desired-state directory."""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import Connector, ConnectorInstance, ConnectorSecret
from kestrel.db.models.finding import Exception_
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
from kestrel.gitops.manifest import (
    ConnectorSpec,
    DesiredState,
    ExceptionSpec,
    GitOpsError,
    PackSpec,
    PolicySpec,
    SecretRef,
    write_manifest,
)
from kestrel.policies.identifiers import validate_policy_id


def export_org_state(
    session: Session,
    org_id: uuid.UUID,
    output_dir: Path,
) -> DesiredState:
    """Dump packs, custom policies, connectors, and policy-scoped exceptions.

    Writes ``kestrel.yaml`` plus ``policies/<slug>.py`` for custom policies.
    Connector secrets appear as field/ref placeholders only — never ciphertext
    or plaintext values.
    """
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    policies_dir = output_dir / "policies"
    if policies_dir.is_symlink():
        raise GitOpsError("export policies directory must not be a symlink")
    policies_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "kestrel.yaml"
    if manifest_path.is_symlink():
        raise GitOpsError("export manifest must not be a symlink")

    packs = _export_packs(session, org_id)
    policies = _export_policies(session, org_id, policies_dir)
    connectors = _export_connectors(session, org_id)
    exceptions = _export_exceptions(session, org_id)

    state = DesiredState(
        packs=packs,
        policies=policies,
        connectors=connectors,
        exceptions=exceptions,
        base_dir=output_dir,
    )
    write_manifest(state, output_dir)
    return state


def _export_packs(session: Session, org_id: uuid.UUID) -> list[PackSpec]:
    names = session.scalars(
        select(Policy.pack_name)
        .where(
            Policy.org_id == org_id,
            Policy.source == PolicySource.PACK,
            Policy.pack_name.is_not(None),
        )
        .distinct()
    ).all()
    return [PackSpec(id=name) for name in sorted(n for n in names if n)]


def _export_policies(session: Session, org_id: uuid.UUID, policies_dir: Path) -> list[PolicySpec]:
    customs = session.scalars(
        select(Policy).where(Policy.org_id == org_id, Policy.source == PolicySource.CUSTOM).order_by(Policy.slug)
    ).all()
    specs: list[PolicySpec] = []
    destinations: set[str] = set()
    writes: list[tuple[Path, str]] = []
    for policy in customs:
        try:
            validate_policy_id(policy.slug)
        except ValueError as exc:
            raise GitOpsError(f"cannot export policy {policy.id}: {exc}") from exc
        version = None
        if policy.current_version_id is not None:
            version = session.get(PolicyVersion, policy.current_version_id)
        if version is None:
            version = session.scalars(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy.id)
                .order_by(PolicyVersion.version.desc())
                .limit(1)
            ).first()
        if version is None:
            continue
        rel = f"policies/{policy.slug.replace('-', '_')}.py"
        destination = policies_dir / f"{policy.slug.replace('-', '_')}.py"
        if destination.is_symlink() or destination.resolve().parent != policies_dir.resolve():
            raise GitOpsError(f"policy export path escapes the policies directory: {policy.slug}")
        if destination.name.casefold() in destinations:
            raise GitOpsError(f"policies map to the same export filename: {destination.name}")
        destinations.add(destination.name.casefold())
        writes.append((destination, version.source_text))
        specs.append(PolicySpec(path=rel, enabled=version.is_enabled, slug=policy.slug))
    # Validate every stored slug and destination before overwriting any policy.
    for destination, source_text in writes:
        destination.write_text(source_text)
    return specs


def _export_connectors(session: Session, org_id: uuid.UUID) -> list[ConnectorSpec]:
    instances = session.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all()
    specs: list[ConnectorSpec] = []
    for instance in instances:
        app = session.get(ApplicationInstance, instance.application_instance_id)
        connector = session.get(Connector, instance.connector_id)
        if app is None or connector is None:
            continue
        secret_rows = session.scalars(
            select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id)
        ).all()
        secrets = [
            SecretRef(field=row.field_name, ref=f"secret:{row.field_name}")
            for row in sorted(secret_rows, key=lambda r: r.field_name)
        ]
        # Strip any accidental secret-looking keys from config on export.
        config = {k: v for k, v in (instance.config or {}).items() if k.lower() not in _REDACT_CONFIG_KEYS}
        specs.append(
            ConnectorSpec(
                name=app.display_name,
                type=connector.name,
                external_tenant_ref=app.external_tenant_ref,
                auth_method=instance.auth_method.value,
                sync_mode=instance.sync_mode.value,
                schedule_cron=instance.schedule_cron,
                config=config,
                secrets=secrets,
            )
        )
    specs.sort(key=lambda c: c.name)
    return specs


def _export_exceptions(session: Session, org_id: uuid.UUID) -> list[ExceptionSpec]:
    rows = session.scalars(
        select(Exception_).where(
            Exception_.org_id == org_id,
            Exception_.finding_id.is_(None),
            Exception_.policy_id.is_not(None),
        )
    ).all()
    specs: list[ExceptionSpec] = []
    for row in rows:
        policy = session.get(Policy, row.policy_id) if row.policy_id else None
        if policy is None:
            continue
        expires = row.expires_at.isoformat() if row.expires_at else None
        specs.append(ExceptionSpec(policy=policy.slug, reason=row.reason, expires_at=expires))
    specs.sort(key=lambda e: (e.policy, e.reason))
    return specs


_REDACT_CONFIG_KEYS = frozenset(
    {
        "token",
        "pat",
        "password",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "private_key",
        "access_token",
        "refresh_token",
    }
)
