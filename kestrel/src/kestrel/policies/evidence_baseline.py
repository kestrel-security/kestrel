# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Minimum evidence contract filled from policy row context at evaluation time.

Policy ``evidence()`` remains authoritative: baseline keys are added only when
missing, so authors can omit boilerplate without starving remediator UI.
"""

from __future__ import annotations

from typing import Any

# RESOURCE_TYPE values used in pack/custom contracts → baseline builder key.
_RESOURCE_TYPE_BASELINE: dict[str, str] = {
    "identity": "identity",
    "grant": "grant",
    "tenant_setting": "setting",
    "setting": "setting",
    "event": "event",
    "application": "application",
    "resource": "resource",
    "oauth_application": "oauth_application",
}


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if key in out:
        return
    if value is None:
        return
    if value == "" or value == {} or value == []:
        return
    out[key] = value


def _put_application(out: dict[str, Any], application: dict[str, Any]) -> None:
    _put(out, "application.type", application.get("type"))
    _put(out, "application.name", application.get("name"))
    _put(out, "application.display_name", application.get("display_name"))
    _put(out, "application.external_tenant_ref", application.get("external_tenant_ref"))
    _put(out, "application.status", application.get("status"))


def _baseline_identity(row: dict[str, Any]) -> dict[str, Any]:
    identity = row.get("identity") or {}
    out: dict[str, Any] = {}
    _put(out, "identity.email", identity.get("email"))
    _put(out, "identity.display_name", identity.get("display_name"))
    _put(out, "identity.mfa_enabled", identity.get("mfa_enabled"))
    _put(out, "identity.is_external", identity.get("is_external"))
    _put(out, "identity.is_disabled", identity.get("is_disabled"))
    _put(out, "identity.identity_type", identity.get("identity_type"))
    roles = row.get("roles")
    if isinstance(roles, list) and roles:
        _put(out, "identity.roles", roles)
    privileged = row.get("privileged_application_types")
    if isinstance(privileged, list) and privileged:
        _put(out, "identity.privileged_application_types", privileged)
    _put_application(out, row.get("application") or {})
    return out


def _baseline_grant(row: dict[str, Any]) -> dict[str, Any]:
    identity = row.get("identity") or {}
    resource = row.get("resource") or {}
    grant = row.get("grant") or {}
    role = row.get("role") or {}
    out: dict[str, Any] = {}
    _put(out, "identity.email", identity.get("email"))
    _put(out, "identity.display_name", identity.get("display_name"))
    _put(out, "identity.mfa_enabled", identity.get("mfa_enabled"))
    _put(out, "identity.is_external", identity.get("is_external"))
    _put(out, "identity.is_disabled", identity.get("is_disabled"))
    _put(out, "resource.name", resource.get("name"))
    _put(out, "resource.resource_type", resource.get("resource_type"))
    _put(out, "grant.granted_via", grant.get("granted_via"))
    _put(out, "grant.permission_level", grant.get("permission_level"))
    _put(out, "role.name", role.get("name"))
    _put_application(out, row.get("application") or {})
    return out


def _baseline_setting(row: dict[str, Any]) -> dict[str, Any]:
    setting = row.get("setting") or {}
    out: dict[str, Any] = {}
    _put(out, "setting.key", setting.get("key"))
    _put(out, "setting.value", setting.get("value"))
    _put(out, "setting.label", setting.get("label"))
    _put(out, "setting.category", setting.get("category"))
    _put(out, "setting.description", setting.get("description"))
    _put_application(out, row.get("application") or {})
    return out


def _baseline_event(row: dict[str, Any]) -> dict[str, Any]:
    event = row.get("event") or {}
    out: dict[str, Any] = {}
    _put(out, "event.action", event.get("action"))
    _put(out, "event.actor_email", event.get("actor_email"))
    _put(out, "event.target_email", event.get("target_email"))
    _put(out, "event.occurred_at", event.get("occurred_at"))
    _put(out, "event.summary", event.get("summary"))
    _put_application(out, row.get("application") or {})
    return out


def _baseline_application(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _put_application(out, row.get("application") or {})
    return out


def _baseline_resource(row: dict[str, Any]) -> dict[str, Any]:
    resource = row.get("resource") or {}
    out: dict[str, Any] = {}
    _put(out, "resource.name", resource.get("name"))
    _put(out, "resource.resource_type", resource.get("resource_type"))
    _put_application(out, row.get("application") or {})
    return out


_BASELINE_BUILDERS = {
    "identity": _baseline_identity,
    "grant": _baseline_grant,
    "setting": _baseline_setting,
    "event": _baseline_event,
    "application": _baseline_application,
    "resource": _baseline_resource,
    "oauth_application": _baseline_application,
}


def merge_baseline_evidence(
    resource_type: str,
    row: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return policy evidence with missing remediator fields filled from the row.

    Policy-provided keys always win (including explicit ``None`` values).
    """
    out: dict[str, Any] = dict(evidence or {})
    kind = _RESOURCE_TYPE_BASELINE.get((resource_type or "").strip().lower())
    if kind is None:
        return out
    builder = _BASELINE_BUILDERS.get(kind)
    if builder is None:
        return out
    baseline = builder(row)
    for key, value in baseline.items():
        if key not in out:
            out[key] = value
    return out
