# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Loads candidate rows for Python policies' resource types as flat,
dotted-path-friendly dicts, joining in exactly the related entities v0
policies need (application, role, resource, and an identity's assigned role
names via the graph).

``RESOURCE_TYPE=application`` loads one row per ApplicationInstance (not the
Application catalog). ``RESOURCE_TYPE=resource`` loads repositories, channels,
drives and sites, with the subject-scoped settings that govern each one
attached. Event rows are bounded by
``KESTREL_POLICY_EVENT_LOOKBACK_DAYS`` (default 90).

Deliberately an ORM-based, client-side-filtered loader rather than a SQL
pushdown query: at vertical-slice scale (one connected org, low thousands of
identities/grants) loading all rows for an org and filtering in Python is
simple, correct, and fast enough. Revisit if per-policy evaluation over large
orgs becomes a bottleneck.
"""

from __future__ import annotations

import enum
import uuid
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from kestrel.db.base import is_active
from kestrel.db.models.access import Grant, Role
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.env import getenv_str

DEFAULT_EVENT_LOOKBACK_DAYS = 90
_ENV_EVENT_LOOKBACK_DAYS = "KESTREL_POLICY_EVENT_LOOKBACK_DAYS"

# Keep in sync with packs/cross-app/.../cross_app_privileged_concentration.py
# (pack modules cannot import kestrel under RestrictedPython).
_PRIVILEGED_ROLE_HINTS = (
    "admin",
    "owner",
    "super_admin",
    "organization_admin",
    "help_desk_admin",
    "groups_admin",
)


def event_lookback_days() -> int:
    """Return the event-policy lookback window in days (env-overridable)."""
    raw = getenv_str(_ENV_EVENT_LOOKBACK_DAYS).strip()
    if not raw:
        return DEFAULT_EVENT_LOOKBACK_DAYS
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError(f"{_ENV_EVENT_LOOKBACK_DAYS} must be a positive integer, got {raw!r}") from exc
    if days < 1:
        raise ValueError(f"{_ENV_EVENT_LOOKBACK_DAYS} must be >= 1, got {days}")
    return days


def event_lookback_cutoff(
    *,
    now: datetime | None = None,
    lookback_days: int | None = None,
) -> datetime:
    """Cutoff timestamp: events with ``occurred_at`` before this are excluded."""
    days = event_lookback_days() if lookback_days is None else lookback_days
    if days < 1:
        raise ValueError(f"lookback_days must be >= 1, got {days}")
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)
    return clock - timedelta(days=days)


def _model_to_dict(instance: Any) -> dict[str, Any]:
    if instance is None:
        return {}
    result: dict[str, Any] = {}
    for column in instance.__table__.columns:
        value = getattr(instance, column.name)
        if isinstance(value, enum.Enum):
            value = value.value
        result[column.name] = value
    return result


def _application_dict(application: Application | None) -> dict[str, Any]:
    if application is None:
        return {}
    return {"type": application.application_type.value, "name": application.name}


def _application_instance_dict(
    instance: ApplicationInstance,
    catalog: Application | None,
) -> dict[str, Any]:
    """Nested ``application`` object including instance display/tenant fields."""
    status_value: str = instance.status.value if isinstance(instance.status, enum.Enum) else str(instance.status)
    base = _application_dict(catalog)
    return {
        **base,
        "display_name": instance.display_name,
        "external_tenant_ref": instance.external_tenant_ref,
        "status": status_value,
    }


def _application_context(session: Session, application_instance_id: uuid.UUID | None) -> dict[str, Any]:
    """Cached per session: every row of a family shares a handful of instances."""
    cache = getattr(session, "_kestrel_app_context_cache", None)
    if cache is None:
        cache = {}
        session._kestrel_app_context_cache = cache  # type: ignore[attr-defined]
    if application_instance_id in cache:
        return dict(cache[application_instance_id])
    value = _application_context_uncached(session, application_instance_id)
    cache[application_instance_id] = value
    return dict(value)


def _application_context_uncached(session: Session, application_instance_id: uuid.UUID | None) -> dict[str, Any]:
    """Catalog + instance fields for identity/grant/setting/event policy rows."""
    if application_instance_id is None:
        return {}
    instance = session.get(ApplicationInstance, application_instance_id)
    if instance is None:
        return {}
    catalog = session.get(Application, instance.application_id)
    return _application_instance_dict(instance, catalog)


def _setting_dict(setting: TenantSetting) -> dict[str, Any]:
    """Flat setting fields for policy authors. JSONB scalars are already Python
    bool/str/number, so `setting.value == false` compares correctly."""
    value = setting.value
    return {
        "key": setting.key,
        "category": setting.category,
        "label": setting.label,
        "value": value,
        # Convenience for authors who prefer an explicit boolean field.
        "value_bool": value if isinstance(value, bool) else None,
        "value_type": setting.value_type,
        "description": setting.description,
    }


def _event_dict(event: ActivityEvent) -> dict[str, Any]:
    return {
        "action": event.action,
        "action_category": event.action_category,
        "actor_email": event.actor_email,
        "actor_provider_id": event.actor_provider_id,
        "target_email": event.target_email,
        "target_type": event.target_type,
        "target_provider_id": event.target_provider_id,
        "occurred_at": event.occurred_at,
        "summary": event.summary,
        # Provider-specific detail the normalizer preserved. Curated
        # action taxonomies are coarse by design, so a policy that needs the
        # branch name, the scope that was added, or the target repo has to read
        # it here. Always a dict, never None, so `event.attributes.get(...)`
        # is safe in a policy without a guard.
        "attributes": event.attributes or {},
    }


def assigned_role_names_by_identity(session: Session, org_id: uuid.UUID) -> dict[uuid.UUID, list[str]]:
    """Every identity's assigned role names, in three queries rather than four
    per identity: identity node -[assigned_role]-> role node -> Role.name.
    """
    identity_node = aliased(GraphNode)
    role_node = aliased(GraphNode)
    rows = session.execute(
        select(identity_node.object_id, Role.name)
        .join(GraphEdge, GraphEdge.source_node_id == identity_node.id)
        .join(role_node, role_node.id == GraphEdge.target_node_id)
        .join(Role, Role.id == role_node.object_id)
        .where(
            identity_node.org_id == org_id,
            identity_node.node_type == GraphNodeType.IDENTITY,
            role_node.node_type == GraphNodeType.ROLE,
            GraphEdge.edge_type == GraphEdgeType.ASSIGNED_ROLE,
            is_active(Role),
        )
    ).all()
    out: dict[uuid.UUID, list[str]] = defaultdict(list)
    for identity_id, role_name in rows:
        if role_name is not None:
            out[identity_id].append(str(role_name))
    return out


def _is_privileged_role_name(name: Any) -> bool:
    if not name:
        return False
    lowered = str(name).lower()
    return any(hint in lowered for hint in _PRIVILEGED_ROLE_HINTS)


def _identity_correlation_key(identity: dict[str, Any]) -> str | None:
    """Email first (cross-app), else provider_object_id (same key across apps)."""
    email = identity.get("email")
    if email is not None:
        key = str(email).strip().lower()
        if key:
            return f"email:{key}"
    provider_id = identity.get("provider_object_id")
    if provider_id is not None:
        key = str(provider_id).strip()
        if key:
            return f"provider:{key}"
    return None


def enrich_privileged_application_types(rows: list[dict[str, Any]]) -> None:
    """Attach ``privileged_application_types`` for cross-app pack policy.

    For each identity with privileged role names, collect distinct
    ``application.type`` values among org identities that share the same email
    (or ``provider_object_id``) and also hold privileged roles. Non-privileged
    rows get ``[]``. Mutates rows in place.
    """
    apps_by_key: dict[str, set[str]] = defaultdict(set)
    privileged_indexes: list[int] = []

    for index, row in enumerate(rows):
        roles = row.get("roles") or []
        if not any(_is_privileged_role_name(role) for role in roles):
            row["privileged_application_types"] = []
            continue
        privileged_indexes.append(index)
        identity = row.get("identity") or {}
        app_type = (row.get("application") or {}).get("type")
        key = _identity_correlation_key(identity)
        if key is not None and app_type:
            apps_by_key[key].add(str(app_type))

    for index in privileged_indexes:
        row = rows[index]
        identity = row.get("identity") or {}
        key = _identity_correlation_key(identity)
        app_type = (row.get("application") or {}).get("type")
        if key is not None and key in apps_by_key:
            row["privileged_application_types"] = sorted(apps_by_key[key])
        elif app_type:
            row["privileged_application_types"] = [str(app_type)]
        else:
            row["privileged_application_types"] = []


# Application types that are an identity provider: the account there is the
# one an offboarding process disables first, so its state is what "this person
# has left" means.
IDP_APPLICATION_TYPES = frozenset({"okta", "google_workspace"})


def attach_cluster_context(session: Session, org_id: uuid.UUID, rows: list[dict[str, Any]]) -> None:
    """Attach ``cluster`` to every identity row: the same person's other accounts.

    This is what makes a cross-application policy expressible in ten lines.
    Each row gains:

    ``cluster.accounts``
        one entry per correlated account (application type, disabled, MFA,
        last active, privileged role names), including this one.
    ``cluster.idp_status``
        ``active`` / ``disabled`` when the person has an identity-provider
        account, ``absent`` when they have none -- the difference between
        "left the company" and "never went through the IdP at all".
    ``cluster.privileged_application_types``
        application types where this person holds a privileged role.

    Rows for orgs whose links have not been built yet get a single-account
    cluster describing themselves, which is true, just less useful.
    """
    from kestrel.db.models.identity_link import IdentityLink

    if not rows:
        return
    by_identity_id = {row["_subject_id"]: row for row in rows}
    links: dict[uuid.UUID, IdentityLink] = {
        found.identity_id: found
        for found in session.scalars(select(IdentityLink).where(IdentityLink.org_id == org_id)).all()
    }
    members_by_key: dict[str, list[uuid.UUID]] = defaultdict(list)
    for member_id, member_link in links.items():
        members_by_key[member_link.cluster_key].append(member_id)

    def account_of(identity_id: uuid.UUID) -> dict[str, Any] | None:
        row = by_identity_id.get(identity_id)
        if row is None:
            return None
        identity = row.get("identity") or {}
        application = row.get("application") or {}
        role_names = row.get("roles") or []
        return {
            "identity_id": str(identity_id),
            "application_type": application.get("type"),
            "application_name": application.get("name"),
            "email": identity.get("email"),
            "display_name": identity.get("display_name"),
            "is_disabled": bool(identity.get("is_disabled")),
            "is_external": bool(identity.get("is_external")),
            "mfa_enabled": identity.get("mfa_enabled"),
            "last_active_at": identity.get("last_active_at"),
            "last_active_source": identity.get("last_active_source"),
            "roles": list(role_names),
            "privileged": any(_is_privileged_role_name(name) for name in role_names),
        }

    # Whether *any* identity provider is connected at all. "No IdP account"
    # only means something once one exists to be missing from.
    idp_connected = any((row.get("application") or {}).get("type") in IDP_APPLICATION_TYPES for row in rows)
    for row in rows:
        identity_id = row["_subject_id"]
        link = links.get(identity_id)
        member_ids = members_by_key.get(link.cluster_key, [identity_id]) if link else [identity_id]
        accounts = [account for member in member_ids if (account := account_of(member)) is not None]
        if not accounts:
            accounts = [account] if (account := account_of(identity_id)) is not None else []
        idp_accounts = [a for a in accounts if a["application_type"] in IDP_APPLICATION_TYPES]
        if not idp_accounts:
            idp_status = "absent"
        elif all(a["is_disabled"] for a in idp_accounts):
            idp_status = "disabled"
        else:
            idp_status = "active"
        row["cluster"] = {
            "accounts": accounts,
            "member_count": len(accounts),
            "application_types": sorted({a["application_type"] for a in accounts if a["application_type"]}),
            "idp_status": idp_status,
            "idp_application_types": sorted({a["application_type"] for a in idp_accounts if a["application_type"]}),
            "privileged_application_types": sorted(
                {a["application_type"] for a in accounts if a["privileged"] and a["application_type"]}
            ),
            "match_kind": link.match_kind if link else "self",
            "idp_connected": idp_connected,
            "representative_identity_id": str(link.representative_identity_id) if link else str(identity_id),
        }


def _oauth_grants_by_identity(session: Session, org_id: uuid.UUID) -> dict[uuid.UUID, list[dict[str, Any]]]:
    """Active OAuth authorizations, keyed by the account that consented.

    An OAuth grant is a credential that does not go through the sign-in path:
    disabling the account does not revoke the token, and no application's admin
    console shows the two facts side by side. Attaching them to the identity row
    is what lets a policy ask whether a person's authorizations outlived them.
    """
    grants = session.scalars(select(OAuthGrant).where(OAuthGrant.org_id == org_id, is_active(OAuthGrant))).all()
    if not grants:
        return {}
    app_ids = {grant.oauth_application_id for grant in grants}
    apps = {app.id: app for app in session.scalars(select(OAuthApplication).where(OAuthApplication.id.in_(app_ids))).all()}
    sensitive_by_app: dict[uuid.UUID, list[str]] = defaultdict(list)
    for scope in session.scalars(
        select(OAuthScope).where(OAuthScope.org_id == org_id, OAuthScope.oauth_application_id.in_(app_ids))
    ).all():
        if scope.is_sensitive:
            sensitive_by_app[scope.oauth_application_id].append(scope.scope_name)

    out: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for grant in grants:
        app = apps.get(grant.oauth_application_id)
        out[grant.identity_id].append(
            {
                "oauth_application_name": app.name if app else None,
                "publisher": app.publisher if app else None,
                "is_verified": bool(app.is_verified) if app else None,
                "sensitive_scope_names": sorted(sensitive_by_app.get(grant.oauth_application_id, [])),
                "granted_at": grant.granted_at,
                "last_used_at": grant.last_used_at,
            }
        )
    for entries in out.values():
        entries.sort(key=lambda entry: str(entry["oauth_application_name"] or ""))
    return dict(out)


def load_identity_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    identities = session.scalars(select(Identity).where(Identity.org_id == org_id, is_active(Identity))).all()
    roles_by_identity = assigned_role_names_by_identity(session, org_id)
    # Settings scoped to one account rather than to the tenant -- the identity
    # counterpart of the per-resource settings attached in load_resource_rows.
    # Google Workspace 2-Step Verification enforcement is per user because that
    # is the only level Google exposes it at.
    settings_by_identity = _settings_by_subject(session, org_id, "identity")
    grants_by_identity = _oauth_grants_by_identity(session, org_id)
    rows = []
    for identity in identities:
        settings = settings_by_identity.get(identity.id, [])
        oauth_grants = grants_by_identity.get(identity.id, [])
        rows.append(
            {
                "_subject_type": "identity",
                "_subject_id": identity.id,
                "identity": _model_to_dict(identity),
                "application": _application_context(session, identity.application_instance_id),
                "roles": roles_by_identity.get(identity.id, []),
                "settings": settings,
                "settings_by_key": {setting["key"]: setting for setting in settings},
                "oauth_grants": oauth_grants,
            }
        )
    enrich_privileged_application_types(rows)
    attach_cluster_context(session, org_id, rows)
    return rows


def load_grant_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    grants = session.scalars(select(Grant).where(Grant.org_id == org_id, is_active(Grant))).all()
    # Bulk-load the three related entities once instead of three gets per grant.
    # A tenant with ten thousand grants issued thirty thousand queries here.
    identities = {
        row.id: row
        for row in session.scalars(
            select(Identity).where(Identity.id.in_({g.identity_id for g in grants if g.identity_id}))
        ).all()
    }
    resources = {
        row.id: row
        for row in session.scalars(
            select(Resource).where(Resource.id.in_({g.resource_id for g in grants if g.resource_id}))
        ).all()
    }
    roles = {
        row.id: row
        for row in session.scalars(select(Role).where(Role.id.in_({g.role_id for g in grants if g.role_id}))).all()
    }
    rows = []
    for grant in grants:
        identity = identities.get(grant.identity_id) if grant.identity_id else None
        resource = resources.get(grant.resource_id) if grant.resource_id else None
        role = roles.get(grant.role_id) if grant.role_id else None

        application_instance_id = None
        if resource is not None:
            application_instance_id = resource.application_instance_id
        elif identity is not None:
            application_instance_id = identity.application_instance_id

        if identity is not None:
            subject_type, subject_id = "identity", identity.id
        elif resource is not None:
            subject_type, subject_id = "resource", resource.id
        else:
            subject_type, subject_id = "identity", grant.id  # defensive fallback, shouldn't normally occur

        rows.append(
            {
                "_subject_type": subject_type,
                "_subject_id": subject_id,
                "grant": {
                    "granted_via": grant.granted_via.value,
                    "permission_level": grant.permission_level,
                },
                "identity": _model_to_dict(identity),
                "resource": _model_to_dict(resource),
                "role": _model_to_dict(role),
                "application": _application_context(session, application_instance_id),
            }
        )
    return rows


def load_setting_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    settings = session.scalars(select(TenantSetting).where(TenantSetting.org_id == org_id, is_active(TenantSetting))).all()
    rows = []
    for setting in settings:
        rows.append(
            {
                "_subject_type": "setting",
                "_subject_id": setting.id,
                "setting": _setting_dict(setting),
                "application": _application_context(session, setting.application_instance_id),
            }
        )
    return rows


def _settings_by_subject(session: Session, org_id: uuid.UUID, subject_type: str) -> dict[uuid.UUID, list[dict[str, Any]]]:
    """Subject-scoped settings, indexed by the entity they govern."""
    settings = session.scalars(
        select(TenantSetting).where(
            TenantSetting.org_id == org_id,
            TenantSetting.subject_type == subject_type,
            TenantSetting.subject_id.is_not(None),
            is_active(TenantSetting),
        )
    ).all()
    by_subject: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for setting in settings:
        if setting.subject_id is not None:
            by_subject[setting.subject_id].append(_setting_dict(setting))
    return by_subject


def load_resource_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """One policy row per Resource for ``RESOURCE_TYPE = "resource"``.

    there was no loader for this at all, so no policy could
    iterate repositories, channels, drives, or SharePoint sites -- the entire
    per-resource posture surface (branch protection, channel sharing, drive
    exposure) was uncheckable no matter what a connector collected.

    Each row carries ``settings``: the subject-scoped settings that govern this
    resource, keyed by setting key as well as listed, so a policy reads
    ``resource.settings_by_key["branch_protection_enabled"]["value"]`` without
    scanning. Resources with no per-resource settings get an empty dict, not a
    missing key.
    """
    resources = session.scalars(select(Resource).where(Resource.org_id == org_id, is_active(Resource))).all()
    if not resources:
        return []

    settings_by_resource = _settings_by_subject(session, org_id, "resource")
    rows = []
    for resource in resources:
        settings = settings_by_resource.get(resource.id, [])
        rows.append(
            {
                "_subject_type": "resource",
                "_subject_id": resource.id,
                "resource": _model_to_dict(resource),
                "settings": settings,
                "settings_by_key": {setting["key"]: setting for setting in settings},
                "application": _application_context(session, resource.application_instance_id),
            }
        )
    return rows


def load_event_rows(
    session: Session,
    org_id: uuid.UUID,
    *,
    lookback_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Load ActivityEvent rows within the configured lookback window.

    Defaults to ``KESTREL_POLICY_EVENT_LOOKBACK_DAYS`` (90). Older events are
    excluded so event-policy evaluation stays bounded.
    """
    cutoff = event_lookback_cutoff(now=now, lookback_days=lookback_days)
    events = session.scalars(
        select(ActivityEvent).where(
            ActivityEvent.org_id == org_id,
            ActivityEvent.occurred_at >= cutoff,
        )
    ).all()
    rows = []
    for event in events:
        rows.append(
            {
                "_subject_type": "event",
                "_subject_id": event.id,
                "event": _event_dict(event),
                "application": _application_context(session, event.application_instance_id),
            }
        )
    return rows


def load_application_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Load one policy row per ApplicationInstance for RESOURCE_TYPE=application.

    Subject id is the instance id (inventory / graph APPLICATION node object).
    Matches reconcile to findings with ``FindingSubjectType.APPLICATION``.
    """
    instances = session.scalars(select(ApplicationInstance).where(ApplicationInstance.org_id == org_id)).all()
    rows = []
    for instance in instances:
        catalog = session.get(Application, instance.application_id)
        rows.append(
            {
                "_subject_type": "application",
                "_subject_id": instance.id,
                "application": _application_instance_dict(instance, catalog),
            }
        )
    return rows


def load_oauth_application_rows(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Load one policy row per OAuthApplication for RESOURCE_TYPE=oauth_application."""
    apps = session.scalars(
        select(OAuthApplication).where(OAuthApplication.org_id == org_id, is_active(OAuthApplication))
    ).all()
    if not apps:
        return []

    app_ids = [a.id for a in apps]
    scopes = session.scalars(
        select(OAuthScope).where(
            OAuthScope.org_id == org_id,
            OAuthScope.oauth_application_id.in_(app_ids),
        )
    ).all()
    sensitive_by_app: dict[uuid.UUID, list[str]] = defaultdict(list)
    for scope in scopes:
        if scope.is_sensitive:
            sensitive_by_app[scope.oauth_application_id].append(scope.scope_name)

    grants = session.scalars(
        select(OAuthGrant).where(
            OAuthGrant.org_id == org_id,
            OAuthGrant.oauth_application_id.in_(app_ids),
            is_active(OAuthGrant),
        )
    ).all()
    last_used_by_app: dict[uuid.UUID, datetime | None] = {}
    grant_count_by_app: dict[uuid.UUID, int] = defaultdict(int)
    for grant in grants:
        grant_count_by_app[grant.oauth_application_id] += 1
        prev = last_used_by_app.get(grant.oauth_application_id)
        if (
            grant.last_used_at is not None and (prev is None or grant.last_used_at > prev)
        ) or grant.oauth_application_id not in last_used_by_app:
            last_used_by_app[grant.oauth_application_id] = grant.last_used_at

    instance_ids = {a.application_instance_id for a in apps}
    instances = {
        i.id: i for i in session.scalars(select(ApplicationInstance).where(ApplicationInstance.id.in_(instance_ids))).all()
    }
    catalog_ids = {i.application_id for i in instances.values()}
    catalogs = {c.id: c for c in session.scalars(select(Application).where(Application.id.in_(catalog_ids))).all()}

    rows: list[dict[str, Any]] = []
    for app in apps:
        instance = instances.get(app.application_instance_id)
        catalog = catalogs.get(instance.application_id) if instance else None
        rows.append(
            {
                "_subject_type": "oauth_application",
                "_subject_id": app.id,
                "oauth_application": {
                    "name": app.name,
                    "publisher": app.publisher,
                    "is_verified": app.is_verified,
                    "provider_object_id": app.provider_object_id,
                },
                "sensitive_scope_names": sorted(sensitive_by_app.get(app.id, [])),
                "last_used_at": last_used_by_app.get(app.id),
                "grant_count": grant_count_by_app.get(app.id, 0),
                "application": _application_instance_dict(instance, catalog) if instance else {},
            }
        )
    return rows


LOADERS: dict[str, Callable[[Session, uuid.UUID], list[dict[str, Any]]]] = {
    "identities": load_identity_rows,
    "grants": load_grant_rows,
    "applications": load_application_rows,
    "oauth_applications": load_oauth_application_rows,
    "resources": load_resource_rows,
    "settings": load_setting_rows,
    "events": load_event_rows,
}

# A policy's ``RESOURCE_TYPE`` -> the LOADERS key that feeds it. Single-sourced
# here because it used to be duplicated in the policy runtime and in custom
# fixture capture, and the two could drift into disagreeing about what an author
# is allowed to write.
RESOURCE_TYPE_TO_FROM_TYPE: dict[str, str] = {
    "identity": "identities",
    "grant": "grants",
    "application": "applications",
    "oauth_application": "oauth_applications",
    "resource": "resources",
    "tenant_setting": "settings",
    "event": "events",
}


def load_rows(session: Session, org_id: uuid.UUID, from_type: str) -> list[dict[str, Any]]:
    loader = LOADERS.get(from_type)
    if loader is None:
        raise ValueError(f"No row loader for from_type '{from_type}' (known: {sorted(LOADERS)})")
    return loader(session, org_id)


class RowCache:
    """One load per row family for a whole evaluation pass.

    Every enabled policy of a given resource type reads the same rows, so
    loading them per policy multiplied the directory scan by the number of
    policies -- roughly a hundred of them in a stock install. Rows are handed
    out as-is, not copied: policies run in a subprocess against a serialized
    snapshot, and the in-process runtime never mutates a row.
    """

    def __init__(self, session: Session, org_id: uuid.UUID) -> None:
        self._session = session
        self._org_id = org_id
        self._rows: dict[str, list[dict[str, Any]]] = {}

    def rows(self, from_type: str) -> list[dict[str, Any]]:
        if from_type not in self._rows:
            loaded = load_rows(self._session, self._org_id, from_type)
            if from_type == "identities":
                from kestrel.policies.runtime.restricted import attach_related_grants

                attach_related_grants(self._session, self._org_id, loaded, grants=self.rows("grants"))
            self._rows[from_type] = loaded
        return self._rows[from_type]
