# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector change-coverage contract (DEC-024).

A connector that collects privilege must prove — via fixtures t0 →
``fixtures/changed/`` t1 — that the normalized diff can surface the
ChangeClasses it claims. Graph edges alone are not coverage.

Validation is offline: it diffs two ``CollectionResult``s and maps creates /
attribute updates onto ChangeClass names without a database.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kestrel.changes.classify import ChangeClass
from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.connectors.sdk.manifest import ConnectorManifest
from kestrel.connectors.sdk.runner import CollectionResult, run_collection

# Entity kinds that imply the connector can emit these classes when fixtures
# stage the corresponding drift. Authors may override with an explicit
# ``change_classes`` list on the manifest.
_INFER_FROM_ENTITY: dict[str, tuple[str, ...]] = {
    "grant": (ChangeClass.ADMIN_GRANTED.value,),
    "group_membership": (ChangeClass.GROUP_MEMBER_ADDED.value,),
    "oauth_grant": (ChangeClass.OAUTH_APP_INSTALLED.value,),
    "setting": (ChangeClass.CONFIG_DRIFT.value, ChangeClass.EXTERNAL_SHARING_ENABLED.value),
}


@dataclass(frozen=True)
class CoverageResult:
    claimed: frozenset[str]
    observed: frozenset[str]
    missing: frozenset[str]
    changed_fixtures_used: bool

    @property
    def ok(self) -> bool:
        return not self.missing


def infer_change_classes(manifest: ConnectorManifest) -> list[str]:
    """Derive claimed classes from ``object_types[].maps_to_entity``."""
    if manifest.change_classes:
        return list(manifest.change_classes)
    claimed: set[str] = set()
    for object_type in manifest.object_types:
        claimed.update(_INFER_FROM_ENTITY.get(object_type.maps_to_entity, ()))
    return sorted(claimed)


def _object_key(obj: NormalizedObject) -> tuple[str, str]:
    if obj.kind in {"group_membership", "grant", "oauth_grant", "oauth_scope"}:
        # Relationship-shaped: fingerprint refs + distinguishing attrs.
        attrs = obj.attributes or {}
        parts = [obj.kind]
        for key in sorted(attrs):
            if key.endswith("_ref") or key in {
                "permission_level",
                "scope_name",
                "role_ref",
                "identity_ref",
                "group_ref",
                "resource_ref",
                "oauth_application_ref",
            }:
                parts.append(f"{key}={attrs[key]}")
        return (obj.kind, "|".join(parts))
    return (obj.kind, obj.provider_id)


def _index(objects: Iterable[NormalizedObject]) -> dict[tuple[str, str], NormalizedObject]:
    return {_object_key(obj): obj for obj in objects}


def observe_change_classes(t0: CollectionResult, t1: CollectionResult) -> set[str]:
    """Map a normalized t0→t1 diff onto ChangeClass values."""
    before = _index(t0.normalized_objects)
    after = _index(t1.normalized_objects)
    observed: set[str] = set()

    for key, obj in after.items():
        if key not in before:
            observed.update(_classes_for_create(obj))
            continue
        prev = before[key]
        if prev.attributes != obj.attributes:
            observed.update(_classes_for_update(prev, obj))

    for key, obj in before.items():
        if key not in after:
            observed.update(_classes_for_delete(obj))

    return observed


def _classes_for_create(obj: NormalizedObject) -> set[str]:
    attrs = obj.attributes or {}
    if obj.kind == "grant":
        level = str(attrs.get("permission_level") or "").lower()
        if level == "admin" or attrs.get("is_privileged") is True:
            return {ChangeClass.ADMIN_GRANTED.value}
        # Role-linked grants without an explicit level still count as admin
        # coverage when the paired role is privileged (normalizer may set
        # permission_level or leave role_ref only).
        if attrs.get("role_ref"):
            return {ChangeClass.ADMIN_GRANTED.value, ChangeClass.ACCESS_GRANTED.value}
        return {ChangeClass.ACCESS_GRANTED.value}
    if obj.kind == "group_membership":
        return {ChangeClass.GROUP_MEMBER_ADDED.value}
    if obj.kind == "oauth_grant":
        return {ChangeClass.OAUTH_APP_INSTALLED.value}
    if obj.kind == "oauth_application":
        return {ChangeClass.OAUTH_APP_INSTALLED.value}
    if obj.kind in {"setting", "tenant_setting"}:
        return {ChangeClass.CONFIG_DRIFT.value}
    if obj.kind == "identity":
        return {ChangeClass.IDENTITY_ADDED.value}
    if obj.kind == "role" and attrs.get("is_privileged"):
        return {ChangeClass.ADMIN_GRANTED.value}
    return set()


def _classes_for_update(prev: NormalizedObject, obj: NormalizedObject) -> set[str]:
    attrs = obj.attributes or {}
    old = prev.attributes or {}
    observed: set[str] = set()
    if obj.kind == "grant":
        old_level = str(old.get("permission_level") or "").lower()
        new_level = str(attrs.get("permission_level") or "").lower()
        rank = {"read": 0, "write": 1, "admin": 2}
        if rank.get(new_level, -1) > rank.get(old_level, -1):
            observed.add(ChangeClass.PRIVILEGE_ESCALATED.value)
            if new_level == "admin":
                observed.add(ChangeClass.ADMIN_GRANTED.value)
        elif rank.get(new_level, -1) < rank.get(old_level, -1):
            observed.add(ChangeClass.PRIVILEGE_REDUCED.value)
    if obj.kind == "identity":
        # Mirrors classify._classify_identity: only an explicit False is a disable.
        if old.get("mfa_enabled") is True and attrs.get("mfa_enabled") is False:
            observed.add(ChangeClass.MFA_DISABLED.value)
        if attrs.get("is_disabled") is True and old.get("is_disabled") is not True:
            observed.add(ChangeClass.IDENTITY_DISABLED.value)
    if obj.kind in {"setting", "tenant_setting"}:
        observed.add(ChangeClass.CONFIG_DRIFT.value)
        category = str(attrs.get("category") or old.get("category") or "")
        if category == "sharing":
            new_val = str(attrs.get("value") or "").lower()
            old_val = str(old.get("value") or "").lower()
            permissive = {"allowed", "anyone", "everyone", "public", "true", "on"}
            if new_val in permissive and old_val not in permissive:
                observed.add(ChangeClass.EXTERNAL_SHARING_ENABLED.value)
    if obj.kind == "oauth_application":
        old_scopes = set(old.get("scopes") or [])
        new_scopes = set(attrs.get("scopes") or [])
        if new_scopes - old_scopes:
            observed.add(ChangeClass.OAUTH_SCOPE_EXPANDED.value)
    return observed


def _classes_for_delete(obj: NormalizedObject) -> set[str]:
    attrs = obj.attributes or {}
    if obj.kind == "grant":
        level = str(attrs.get("permission_level") or "").lower()
        if level == "admin" or attrs.get("role_ref"):
            return {ChangeClass.ADMIN_REVOKED.value}
        return {ChangeClass.ACCESS_REVOKED.value}
    if obj.kind == "group_membership":
        return {ChangeClass.GROUP_MEMBER_REMOVED.value}
    if obj.kind == "oauth_grant":
        return {ChangeClass.OAUTH_APP_REVOKED.value}
    if obj.kind == "identity":
        return {ChangeClass.IDENTITY_REMOVED.value}
    return set()


def _merge_fixture_dirs(base: Path, overlay: Path, dest: Path) -> None:
    shutil.copytree(base, dest)
    if not overlay.exists():
        return
    for path in overlay.rglob("*"):
        if path.is_file():
            rel = path.relative_to(overlay)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def validate_change_coverage(
    *,
    connector: Any,
    manifest: ConnectorManifest,
    fixtures_dir: Path,
    build_fixture_transport: Any,
    changed_subdir: str = "changed",
) -> CoverageResult:
    """Collect t0 (base fixtures) and t1 (overlay), then check claimed classes."""
    claimed = frozenset(infer_change_classes(manifest))
    if not claimed:
        return CoverageResult(
            claimed=frozenset(),
            observed=frozenset(),
            missing=frozenset(),
            changed_fixtures_used=False,
        )

    changed_dir = fixtures_dir / changed_subdir
    if not changed_dir.is_dir():
        return CoverageResult(
            claimed=claimed,
            observed=frozenset(),
            missing=claimed,
            changed_fixtures_used=False,
        )

    t0 = run_collection(
        connector,
        config=dict(manifest.example_config),
        transport_override=build_fixture_transport(),
    )

    with tempfile.TemporaryDirectory(prefix="kestrel-coverage-") as tmp:
        merged = Path(tmp) / "fixtures"
        _merge_fixture_dirs(fixtures_dir, changed_dir, merged)
        # Prefer a transport that accepts fixtures_dir when the builder supports it.
        try:
            transport_t1 = build_fixture_transport(fixtures_dir=merged)
        except TypeError:
            transport_t1 = build_fixture_transport()
            # Last resort: rebuild mapping against merged dir if the builder
            # ignores kwargs — callers should accept fixtures_dir.
            from kestrel.connectors.sdk.fixtures import FixtureTransport

            if isinstance(transport_t1, FixtureTransport):
                transport_t1 = FixtureTransport(fixtures_dir=merged, mapping=dict(transport_t1.mapping))
        t1 = run_collection(
            connector,
            config=dict(manifest.example_config),
            transport_override=transport_t1,
        )

    observed = frozenset(observe_change_classes(t0, t1))
    missing = frozenset(c for c in claimed if c not in observed)
    return CoverageResult(
        claimed=claimed,
        observed=observed,
        missing=missing,
        changed_fixtures_used=True,
    )
