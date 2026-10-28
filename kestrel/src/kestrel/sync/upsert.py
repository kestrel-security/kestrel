# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Upserts NormalizedObjects into their corresponding entity tables.

Provenance-tracked entities (identity/group/role/resource/permission/
oauth_application) are upserted first, keyed by
(application_instance_id, provider_object_id), populating an
UpsertContext.id_maps[kind][provider_id] -> Kestrel UUID map.
Relationship-shaped objects (group_membership/grant/oauth_scope/oauth_grant)
are upserted second, resolving their `_ref` attributes through that same map
-- they can't be processed in the same pass since a grant may reference an
identity, group, and resource that were all normalized in this same run.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import ColumnElement, String, and_, any_, delete, literal, or_, select, update
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.access import Grant, GrantedVia, Group, GroupMembership, Permission, Role
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.connector import ConnectorRun
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity, IdentityType, ServiceAccount, coerce_worker_type
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.resource import Resource, ResourceType, ResourceVisibility
from kestrel.db.models.setting import TenantSetting
from kestrel.policies.runtime.helpers import TRUSTED_ACTIVITY_SOURCES

PROVENANCE_KINDS = (
    "identity",
    "group",
    "role",
    "resource",
    "permission",
    "oauth_application",
    "setting",
    "event",
)

# Join-shaped kinds diffed in the second pass. These carry the security-
# interesting half of change detection -- a new admin, a privilege bump, and an
# OAuth install are all edges appearing or changing, not entity attributes
# moving -- so they land in the same ``events`` feed as entity drift.
RELATIONSHIP_KINDS = ("group_membership", "grant", "oauth_grant")

# An observation that an account did something at a point in time, emitted by
# audit-log and usage-report normalizers (``{identity_ref, observed_at,
# source}``). It has no table: the run's latest observation per account is
# max-merged onto ``identities.last_active_at`` so an events-only incremental
# sync keeps "last sign-in" current for providers whose directory carries no
# such field (GitHub), and activity-event retention can never erase it.
IDENTITY_ACTIVITY_KIND = "identity_activity"

# Every normalized kind the pipeline persists, across both write paths: the
# provenance pass and the relationship pass. `oauth_scope` and
# `identity_activity` belong to neither tuple above -- scopes are reconciled
# against their owning application and activity is folded onto the identity
# inside `upsert_relationship_objects` rather than upserted row by row -- so
# neither tuple alone is the vocabulary.
#
# This is the set a manifest's `maps_to_entity` must draw from.
NORMALIZED_KINDS = frozenset({*PROVENANCE_KINDS, *RELATIONSHIP_KINDS, "oauth_scope", IDENTITY_ACTIVITY_KIND})

# Audit-log rows are append-only historical facts — never treat absence from
# a later collection window as a deletion.
APPEND_ONLY_KINDS = frozenset({"event"})

# Kinds that are upserted like any other entity but must not write ``events``
# rows. Audit-log collection appends one ActivityEvent per provider log line; if
# each of those also emitted an EntityChange, a chatty tenant would fill the
# Changes feed with ``other`` / ``low`` rows. They are hidden from the default
# view, but ``change_feed`` applies FEED_SCAN_CAP in SQL *before* classification,
# so they consume the scan budget and push real drift out of the window entirely.
#
# Provider audit logs reach operators through event policies in Findings and, per
# DEC-024, as the optional actor overlay on a diff row -- never as a
# change row of their own.
NON_FEED_KINDS = frozenset({"event"})

# Telemetry timestamps that update on every login / token refresh. Still written
# onto the entity so policies can use them; they must not emit Events or they
# drown the Changes feed in ``other`` / ``low`` rows (DEC-024).
VOLATILE_FIELDS = frozenset({"last_active_at", "last_active_source", "created_at_source"})

# Identity attributes that map to a column of their own; everything else a
# normalizer emits lands in ``identities.attributes``.
_IDENTITY_COLUMN_KEYS = frozenset(
    {
        "identity_type",
        "email",
        "display_name",
        "is_disabled",
        "mfa_enabled",
        "is_external",
        "created_at_source",
        "last_active_at",
        "last_active_source",
        "worker_type",
        "department",
        "title",
        "manager_email",
        "disabled_at",
        "expires_at",
    }
)
# Reference attributes the relationship pass consumes; not data about the account.
_IDENTITY_REF_KEYS = frozenset({"owner_identity_ref"})

# Unions, not bare `type`/instances, so mypy can resolve the ProvenanceMixin
# attributes (application_instance_id, provider_object_id, last_seen_at)
# these otherwise-unrelated classes all share. SQLAlchemy's `select()`
# stubs don't preserve a Union[type[...], ...] input's specificity (they
# widen the row type to the common declarative Base), so query results
# against `model: ProvenanceModel` are `cast()` back to ProvenanceEntity
# below -- correct at runtime, just more precise than what select() infers.
# Bound on ids per IN (...) list, well under psycopg's 65,535 bind parameters.
_IN_CHUNK = 10_000

ProvenanceModel = (
    type[Identity]
    | type[Group]
    | type[Role]
    | type[Resource]
    | type[Permission]
    | type[OAuthApplication]
    | type[TenantSetting]
    | type[ActivityEvent]
)
ProvenanceEntity = Identity | Group | Role | Resource | Permission | OAuthApplication | TenantSetting | ActivityEvent

_MODEL_BY_KIND: dict[str, ProvenanceModel] = {
    "identity": Identity,
    "group": Group,
    "role": Role,
    "resource": Resource,
    "permission": Permission,
    "oauth_application": OAuthApplication,
    "setting": TenantSetting,
    "event": ActivityEvent,
}

# Relationship rows aren't provenance-tracked (no provider_object_id -- they're
# identified by their endpoints), but they do carry first/last_seen_at and a
# source run, which is all detect_deletions needs.
RelationshipModel = type[GroupMembership] | type[Grant] | type[OAuthGrant]
RelationshipEntity = GroupMembership | Grant | OAuthGrant

_RELATIONSHIP_MODEL_BY_KIND: dict[str, RelationshipModel] = {
    "group_membership": GroupMembership,
    "grant": Grant,
    "oauth_grant": OAuthGrant,
}


@dataclass
class UpsertContext:
    org_id: uuid.UUID
    application_instance_id: uuid.UUID
    connector_run_id: uuid.UUID
    connector_instance_id: uuid.UUID
    id_maps: dict[str, dict[str, uuid.UUID]] = field(default_factory=lambda: {kind: {} for kind in PROVENANCE_KINDS})
    # Whether an OAuth app this run upserted with no scopes at all has truly
    # lost them. Only a complete, non-incremental run whose scope collection
    # was not skipped can say so; otherwise absence proves nothing and only
    # apps that reported at least one scope are reconciled.
    reconcile_absent_scopes: bool = False
    # Relationship objects dropped because a reference they named did not
    # resolve (the endpoint appeared mid-sync, or was not collected), by kind.
    skipped_unresolved: dict[str, int] = field(default_factory=dict)


@dataclass
class EntityChange:
    entity_type: str
    entity_id: uuid.UUID
    change_type: ChangeType
    field_changes: list[dict[str, Any]] = field(default_factory=list)


def _json_safe(value: Any) -> Any:
    """Coerce values that JSONB cannot store (datetime, enum, UUID).

    Identity last_active_at / created_at_source are datetime columns. Diffing
    them without this helper put raw datetime objects into Event.field_changes
    and aborted live Okta sync at flush (`Object of type datetime is not JSON
    serializable`) after collection had already succeeded.
    """
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _parse_optional_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    raise TypeError(f"Expected datetime or ISO string, got {type(value)!r}")


def _identity_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Provider extras with no column of their own, JSON-safe, sorted, nulls dropped.

    Dropping ``None`` means a key the provider stops reporting disappears
    rather than lingering as ``null``, and sorted keys keep JSONB equality (and
    so the change diff) stable from run to run.
    """
    return {
        key: _json_safe(value)
        for key in sorted(attributes)
        if key not in _IDENTITY_COLUMN_KEYS and key not in _IDENTITY_REF_KEYS and (value := attributes[key]) is not None
    }


def merge_last_active(
    existing_at: datetime | None,
    existing_source: str | None,
    incoming_at: datetime | None,
    incoming_source: str | None,
) -> tuple[datetime | None, str | None]:
    """The ``(last_active_at, last_active_source)`` to store after a new observation.

    Activity only ever moves forward: an observation the provider no longer
    repeats (a GitHub member re-sync carries no sign-in field; an audit-log
    window that has rolled past the last action) must not erase what an earlier
    run learned. A trusted source (``TRUSTED_ACTIVITY_SOURCES``) always beats an
    untrusted one, and between two of the same trust the later timestamp wins.
    """
    if incoming_at is None:
        return existing_at, existing_source
    if existing_at is None:
        return incoming_at, incoming_source
    existing_trusted = existing_source in TRUSTED_ACTIVITY_SOURCES
    incoming_trusted = incoming_source in TRUSTED_ACTIVITY_SOURCES
    if existing_trusted and not incoming_trusted:
        return existing_at, existing_source
    if incoming_trusted and not existing_trusted:
        return incoming_at, incoming_source
    if incoming_at > existing_at:
        return incoming_at, incoming_source
    return existing_at, existing_source


def _entity_kwargs(
    kind: str, attributes: dict[str, Any], *, id_maps: dict[str, dict[str, uuid.UUID]] | None = None
) -> dict[str, Any]:
    if kind == "identity":
        worker_type = coerce_worker_type(attributes.get("worker_type"))
        return {
            "identity_type": IdentityType(attributes["identity_type"]),
            "email": attributes.get("email"),
            "display_name": attributes.get("display_name"),
            "is_disabled": attributes.get("is_disabled", False),
            "mfa_enabled": attributes.get("mfa_enabled"),
            "is_external": attributes.get("is_external", False),
            "created_at_source": _parse_optional_datetime(attributes.get("created_at_source")),
            "last_active_at": _parse_optional_datetime(attributes.get("last_active_at")),
            "last_active_source": attributes.get("last_active_source"),
            "worker_type": worker_type,
            "worker_type_source": "connector" if worker_type != "unknown" else None,
            "department": attributes.get("department") or None,
            "title": attributes.get("title") or None,
            "manager_email": attributes.get("manager_email") or None,
            "disabled_at": _parse_optional_datetime(attributes.get("disabled_at")),
            "expires_at": _parse_optional_datetime(attributes.get("expires_at")),
            # The provider's own answer is kept beside the extras so a
            # classification rule that stops matching can fall back to it.
            "attributes": {**_identity_attributes(attributes), "connector_worker_type": worker_type},
        }
    if kind == "group":
        return {"name": attributes["name"], "description": attributes.get("description")}
    if kind == "role":
        return {"name": attributes["name"], "is_privileged": attributes.get("is_privileged", False)}
    if kind == "resource":
        return {
            "resource_type": ResourceType(attributes["resource_type"]),
            "name": attributes["name"],
            "visibility": ResourceVisibility(attributes["visibility"]) if attributes.get("visibility") else None,
            "is_sensitive": attributes.get("is_sensitive"),
            "config": attributes.get("config") or {},
        }

    if kind == "permission":
        return {
            "name": attributes["name"],
            "action": attributes["action"],
            "description": attributes.get("description"),
        }
    if kind == "oauth_application":
        owner_id = None
        owner_ref = attributes.get("owner_identity_ref")
        if owner_ref and id_maps is not None:
            owner_id = id_maps["identity"].get(owner_ref)
        return {
            "name": attributes["name"],
            "publisher": attributes.get("publisher"),
            "is_verified": attributes.get("is_verified"),
            "owner_identity_id": owner_id,
        }
    if kind == "setting":
        # A setting that governs one entity rather than the whole tenant
        # names it by kind + provider id; the id map resolves that to
        # a Kestrel id. Unresolvable means the subject was not in this run --
        # store the setting tenant-wide rather than dropping it, the same way
        # the graph writer skips an edge whose endpoint is missing.
        subject_type = attributes.get("subject_type")
        subject_ref = attributes.get("subject_ref")
        subject_id = None
        if subject_type and subject_ref and id_maps is not None:
            subject_id = id_maps.get(subject_type, {}).get(subject_ref)
        return {
            "key": attributes["key"],
            "category": attributes["category"],
            "label": attributes["label"],
            "value": attributes["value"],
            "value_type": attributes["value_type"],
            "description": attributes.get("description"),
            "subject_type": subject_type if subject_id is not None else None,
            "subject_id": subject_id,
        }
    if kind == "event":
        occurred_at = _parse_optional_datetime(attributes.get("occurred_at"))
        if occurred_at is None:
            raise ValueError("event.occurred_at is required")
        return {
            "action": attributes["action"],
            "action_category": attributes["action_category"],
            "actor_email": attributes.get("actor_email"),
            "actor_provider_id": attributes.get("actor_provider_id"),
            "target_email": attributes.get("target_email"),
            "target_type": attributes.get("target_type"),
            "target_provider_id": attributes.get("target_provider_id"),
            "occurred_at": occurred_at,
            "summary": attributes["summary"],
            "attributes": attributes.get("attributes") or {},
        }
    raise ValueError(f"No entity kwargs mapping for kind '{kind}'")


def _preserve_sensitivity_override(existing: Any, new_kwargs: dict[str, Any]) -> None:
    """An operator's sensitivity decision outranks the connector heuristic.

    ``PATCH /resources/{id}`` writes ``config.sensitivity_override``; every
    later sync would otherwise overwrite ``is_sensitive`` with the heuristic's
    answer and quietly undo the review.
    """
    config = getattr(existing, "config", None) or {}
    override = config.get("sensitivity_override")
    if override is None:
        return
    new_kwargs["is_sensitive"] = bool(override)
    merged = dict(new_kwargs.get("config") or {})
    merged["sensitivity_override"] = bool(override)
    merged["sensitivity_source"] = "operator"
    if config.get("sensitivity_override_by"):
        merged["sensitivity_override_by"] = config["sensitivity_override_by"]
    if config.get("sensitivity_override_at"):
        merged["sensitivity_override_at"] = config["sensitivity_override_at"]
    new_kwargs["config"] = merged


def _reconcile_identity_update(existing: Identity, new_kwargs: dict[str, Any]) -> None:
    """Fields on an identity that a later sync must merge rather than overwrite.

    ``last_active_at`` only moves forward (``merge_last_active``), and a worker
    type an operator classification rule assigned (``worker_type_source``
    starting with ``rule:``) outranks the provider's profile field: the
    reclassification pass owns that column until the rule stops matching.
    """
    new_kwargs["last_active_at"], new_kwargs["last_active_source"] = merge_last_active(
        existing.last_active_at,
        existing.last_active_source,
        new_kwargs.get("last_active_at"),
        new_kwargs.get("last_active_source"),
    )
    if (existing.worker_type_source or "").startswith("rule:"):
        new_kwargs["worker_type"] = existing.worker_type
        new_kwargs["worker_type_source"] = existing.worker_type_source


def _attribute_changes(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-key diff of ``identities.attributes`` so the Changes feed names the
    attribute that moved rather than dumping two JSON blobs."""
    return [
        {"field": f"attributes.{key}", "old": _json_safe(old.get(key)), "new": _json_safe(new.get(key))}
        for key in sorted(set(old) | set(new))
        if old.get(key) != new.get(key)
    ]


def _provenance_sort_key(obj: NormalizedObject) -> int:
    """Order objects so a kind is upserted before the kinds that reference it.

    PROVENANCE_KINDS is already in dependency order -- identity before
    oauth_application (`owner_identity_ref`), resource before setting
    (`subject_ref`). Without this the resolution depends on the order a
    normalizer happened to emit in, which is not something a connector author
    should have to know about. Unknown kinds sort last; they are skipped in the
    loop anyway.
    """
    try:
        return PROVENANCE_KINDS.index(obj.kind)
    except ValueError:
        return len(PROVENANCE_KINDS)


def _any_uuid(column: Any, values: Iterable[uuid.UUID]) -> ColumnElement[bool]:
    """``column = ANY(:array)``: one bind parameter however many ids there
    are, so a 100k-row tenant stays under psycopg's 65,535-parameter limit."""
    return cast("ColumnElement[bool]", column == any_(literal(list(values), ARRAY(PG_UUID(as_uuid=True)))))


def _any_str(column: Any, values: Iterable[str]) -> ColumnElement[bool]:
    return cast("ColumnElement[bool]", column == any_(literal(list(values), ARRAY(String()))))


def _load_provenance_rows(
    session: Session, kind: str, provider_ids: set[str], ctx: UpsertContext
) -> dict[str, ProvenanceEntity]:
    """This instance's existing rows of ``kind`` for the given provider ids,
    in one query rather than one per object."""
    if not provider_ids:
        return {}
    model = _MODEL_BY_KIND[kind]
    rows = cast(
        "list[ProvenanceEntity]",
        list(
            session.scalars(
                select(model).where(
                    model.application_instance_id == ctx.application_instance_id,
                    _any_str(model.provider_object_id, provider_ids),
                )
            ).all()
        ),
    )
    return {row.provider_object_id: row for row in rows}


def upsert_provenance_objects(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> list[EntityChange]:
    changes: list[EntityChange] = []
    now = datetime.now(UTC)

    provider_ids_by_kind: dict[str, set[str]] = {}
    for obj in objects:
        if obj.kind in _MODEL_BY_KIND:
            provider_ids_by_kind.setdefault(obj.kind, set()).add(obj.provider_id)
    known: dict[str, dict[str, ProvenanceEntity]] = {}
    current_kind: str | None = None

    for obj in sorted(objects, key=_provenance_sort_key):
        if obj.kind not in _MODEL_BY_KIND:
            continue
        if obj.kind != current_kind:
            # Kinds are processed in dependency order; flushing at each
            # boundary writes, e.g., identities before the OAuth apps whose
            # owner_identity_id points at them.
            if current_kind is not None:
                session.flush()
            current_kind = obj.kind
            known[obj.kind] = _load_provenance_rows(session, obj.kind, provider_ids_by_kind[obj.kind], ctx)
        model = _MODEL_BY_KIND[obj.kind]
        new_kwargs = _entity_kwargs(obj.kind, obj.attributes, id_maps=ctx.id_maps)

        existing = known[obj.kind].get(obj.provider_id)

        if existing is None:
            row = model(
                id=uuid.uuid4(),
                org_id=ctx.org_id,
                application_instance_id=ctx.application_instance_id,
                provider_object_id=obj.provider_id,
                source_connector_run_id=ctx.connector_run_id,
                raw_source=obj.raw_source,
                first_seen_at=now,
                last_seen_at=now,
                **new_kwargs,
            )
            session.add(row)
            # A provider repeating an object within one run updates this row
            # rather than inserting a second one.
            known[obj.kind][obj.provider_id] = row
            if obj.kind not in NON_FEED_KINDS:
                changes.append(EntityChange(entity_type=obj.kind, entity_id=row.id, change_type=ChangeType.CREATED))
        else:
            revived = existing.deleted_at is not None
            if obj.kind == "resource":
                _preserve_sensitivity_override(existing, new_kwargs)
            if obj.kind == "identity":
                _reconcile_identity_update(cast("Identity", existing), new_kwargs)
            field_changes = []
            for key, new_value in new_kwargs.items():
                old_value = getattr(existing, key)
                if key == "attributes":
                    field_changes.extend(_attribute_changes(old_value or {}, new_value or {}))
                elif old_value != new_value and key not in VOLATILE_FIELDS:
                    field_changes.append(
                        {
                            "field": key,
                            "old": _json_safe(old_value),
                            "new": _json_safe(new_value),
                        }
                    )
                setattr(existing, key, new_value)
            existing.last_seen_at = now
            existing.source_connector_run_id = ctx.connector_run_id
            existing.raw_source = obj.raw_source
            existing.deleted_at = None
            row = existing
            if revived and obj.kind not in NON_FEED_KINDS:
                # The provider reports it again after a tombstone: that is a
                # reappearance, not an edit of something that was there all along.
                changes.append(EntityChange(entity_type=obj.kind, entity_id=row.id, change_type=ChangeType.CREATED))
            elif field_changes and obj.kind not in NON_FEED_KINDS:
                changes.append(
                    EntityChange(
                        entity_type=obj.kind,
                        entity_id=row.id,
                        change_type=ChangeType.UPDATED,
                        field_changes=field_changes,
                    )
                )

        ctx.id_maps[obj.kind][obj.provider_id] = row.id

    session.flush()
    return changes


def _scope_reconciled_app_ids(objects: list[NormalizedObject], ctx: UpsertContext) -> set[uuid.UUID]:
    """OAuth apps whose scope set this run is authoritative for."""
    if ctx.reconcile_absent_scopes:
        return set(ctx.id_maps["oauth_application"].values())
    return {
        app_id
        for obj in objects
        if obj.kind == "oauth_scope"
        and (app_id := ctx.id_maps["oauth_application"].get(obj.attributes["oauth_application_ref"])) is not None
    }


def _existing_scope_sets(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> dict[uuid.UUID, set[str]]:
    """Scope names already on record for every OAuth app this run reconciles.

    Captured before the upsert loop writes anything, since the scope diff
    compares against the pre-run state.
    """
    app_ids = _scope_reconciled_app_ids(objects, ctx)
    if not app_ids:
        return {}

    existing: dict[uuid.UUID, set[str]] = {app_id: set() for app_id in app_ids}
    rows = session.execute(
        select(OAuthScope.oauth_application_id, OAuthScope.scope_name).where(
            OAuthScope.org_id == ctx.org_id,
            OAuthScope.oauth_application_id.in_(app_ids),
        )
    ).all()
    for app_id, scope_name in rows:
        existing[app_id].add(scope_name)
    return existing


GrantKey = tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None, uuid.UUID | None, GrantedVia]


def _resolve_ref(ctx: UpsertContext, kind: str, ref: Any) -> tuple[bool, uuid.UUID | None]:
    """(ok, id): an absent ref is fine (None); a ref that names nothing is not."""
    if not ref:
        return True, None
    resolved = ctx.id_maps[kind].get(ref)
    return resolved is not None, resolved


def _membership_key(attrs: dict[str, Any], ctx: UpsertContext) -> tuple[uuid.UUID, uuid.UUID] | None:
    group_id = ctx.id_maps["group"].get(attrs["group_ref"])
    identity_id = ctx.id_maps["identity"].get(attrs["identity_ref"])
    if group_id is None or identity_id is None:
        return None
    return group_id, identity_id


def _grant_key(attrs: dict[str, Any], ctx: UpsertContext) -> GrantKey | None:
    """(identity, resource, role, source group, granted_via), or None when a
    reference the provider gave does not resolve. Matches the grant table's
    ``uq_grants_natural_key``."""
    identity = _resolve_ref(ctx, "identity", attrs.get("identity_ref"))
    resource = _resolve_ref(ctx, "resource", attrs.get("resource_ref"))
    role = _resolve_ref(ctx, "role", attrs.get("role_ref"))
    group = _resolve_ref(ctx, "group", attrs.get("source_group_ref"))
    if not (identity[0] and resource[0] and role[0] and group[0]):
        return None
    return identity[1], resource[1], role[1], group[1], GrantedVia(attrs["granted_via"])


def _oauth_grant_key(attrs: dict[str, Any], ctx: UpsertContext) -> tuple[uuid.UUID, uuid.UUID] | None:
    app_id = ctx.id_maps["oauth_application"].get(attrs["oauth_application_ref"])
    identity_id = ctx.id_maps["identity"].get(attrs["identity_ref"])
    if app_id is None or identity_id is None:
        return None
    return app_id, identity_id


@dataclass
class _ExistingRelationships:
    memberships: dict[tuple[uuid.UUID, uuid.UUID], GroupMembership] = field(default_factory=dict)
    grants: dict[GrantKey, Grant] = field(default_factory=dict)
    scopes: dict[tuple[uuid.UUID, str], OAuthScope] = field(default_factory=dict)
    oauth_grants: dict[tuple[uuid.UUID, uuid.UUID], OAuthGrant] = field(default_factory=dict)


def _load_relationship_rows(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> _ExistingRelationships:
    """Every existing relationship row this run could match, one query per
    kind, keyed by the natural key the upsert looks rows up by."""
    loaded = _ExistingRelationships()
    membership_groups: set[uuid.UUID] = set()
    grant_keys: set[GrantKey] = set()
    oauth_apps: set[uuid.UUID] = set()
    for obj in objects:
        if obj.kind == "group_membership":
            if (membership_key := _membership_key(obj.attributes, ctx)) is not None:
                membership_groups.add(membership_key[0])
        elif obj.kind == "grant":
            if (grant_key := _grant_key(obj.attributes, ctx)) is not None:
                grant_keys.add(grant_key)
        elif obj.kind in ("oauth_scope", "oauth_grant"):
            app_id = ctx.id_maps["oauth_application"].get(obj.attributes["oauth_application_ref"])
            if app_id is not None:
                oauth_apps.add(app_id)

    if membership_groups:
        for membership in session.scalars(
            select(GroupMembership).where(_any_uuid(GroupMembership.group_id, membership_groups))
        ).all():
            loaded.memberships.setdefault((membership.group_id, membership.identity_id), membership)

    if grant_keys:
        # A matching grant shares at least one non-null endpoint with a key
        # this run produced, or has none at all; fetch that superset and
        # match on the full key in Python.
        identities = {key[0] for key in grant_keys if key[0] is not None}
        resources = {key[1] for key in grant_keys if key[1] is not None}
        roles = {key[2] for key in grant_keys if key[2] is not None}
        groups = {key[3] for key in grant_keys if key[3] is not None}
        candidates = session.scalars(
            select(Grant).where(
                Grant.org_id == ctx.org_id,
                or_(
                    _any_uuid(Grant.identity_id, identities),
                    _any_uuid(Grant.resource_id, resources),
                    _any_uuid(Grant.role_id, roles),
                    _any_uuid(Grant.source_group_id, groups),
                    and_(
                        Grant.identity_id.is_(None),
                        Grant.resource_id.is_(None),
                        Grant.role_id.is_(None),
                        Grant.source_group_id.is_(None),
                    ),
                ),
            )
        ).all()
        for grant in candidates:
            candidate_key: GrantKey = (
                grant.identity_id,
                grant.resource_id,
                grant.role_id,
                grant.source_group_id,
                grant.granted_via,
            )
            if candidate_key in grant_keys:
                loaded.grants.setdefault(candidate_key, grant)

    if oauth_apps:
        for scope in session.scalars(select(OAuthScope).where(_any_uuid(OAuthScope.oauth_application_id, oauth_apps))).all():
            loaded.scopes.setdefault((scope.oauth_application_id, scope.scope_name), scope)
        for oauth_grant in session.scalars(
            select(OAuthGrant).where(_any_uuid(OAuthGrant.oauth_application_id, oauth_apps))
        ).all():
            loaded.oauth_grants.setdefault((oauth_grant.oauth_application_id, oauth_grant.identity_id), oauth_grant)
    return loaded


def upsert_relationship_objects(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> list[EntityChange]:
    """Upserts group_membership, grant, oauth_scope, and oauth_grant rows.

    Returns the relationship half of the run's diff. Appearances are CREATED and
    mutations (a grant's permission_level, an OAuth app's scope set) are UPDATED;
    disappearances are found later by ``detect_deletions`` via last_seen_at, since
    a relationship that's gone from the provider simply stops being collected.

    OAuth scope churn is attributed to the owning ``oauth_application`` rather
    than emitted per-scope: "this app went from read:user to repo + admin:org" is
    the reviewable unit, not two unrelated scope rows.
    """
    now = datetime.now(UTC)
    changes: list[EntityChange] = []
    apply_identity_activity(session, objects, ctx)
    _apply_service_account_owners(session, objects, ctx)
    previous_scopes = _existing_scope_sets(session, objects, ctx)
    collected_scopes: dict[uuid.UUID, set[str]] = {app_id: set() for app_id in previous_scopes}
    # Existing rows, loaded once per kind and keyed by natural key. Rows this
    # run adds go into the same maps: sessions run with autoflush off, so a
    # pending row is invisible to a query, and a relationship reported twice
    # in one run (Google Workspace emits one oauth_scope per user token) must
    # update the first copy rather than insert a duplicate.
    existing = _load_relationship_rows(session, objects, ctx)
    memberships = existing.memberships
    grants = existing.grants
    scope_rows = existing.scopes
    oauth_grants = existing.oauth_grants

    def _skip_unresolved(kind: str) -> None:
        ctx.skipped_unresolved[kind] = ctx.skipped_unresolved.get(kind, 0) + 1

    for obj in objects:
        if obj.kind == "group_membership":
            membership_key = _membership_key(obj.attributes, ctx)
            if membership_key is None:
                # The member or group appeared between this run's collections
                # (or was not collected); the next run picks it up.
                _skip_unresolved(obj.kind)
                continue
            member_group_id, member_identity_id = membership_key
            existing_membership = memberships.get(membership_key)
            if existing_membership is None:
                membership = GroupMembership(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    group_id=member_group_id,
                    identity_id=member_identity_id,
                    source_connector_run_id=ctx.connector_run_id,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(membership)
                memberships[membership_key] = membership
                changes.append(
                    EntityChange(
                        entity_type="group_membership",
                        entity_id=membership.id,
                        change_type=ChangeType.CREATED,
                    )
                )
            else:
                if existing_membership.deleted_at is not None:
                    changes.append(
                        EntityChange(
                            entity_type="group_membership",
                            entity_id=existing_membership.id,
                            change_type=ChangeType.CREATED,
                        )
                    )
                existing_membership.deleted_at = None
                existing_membership.last_seen_at = now
                existing_membership.source_connector_run_id = ctx.connector_run_id

        elif obj.kind == "grant":
            attrs = obj.attributes
            grant_key = _grant_key(attrs, ctx)
            if grant_key is None:
                # A reference that names nothing must not become NULL: a grant
                # with no resource reads as org-wide access.
                _skip_unresolved(obj.kind)
                continue
            grant_identity_id, grant_resource_id, grant_role_id, grant_source_group_id, granted_via = grant_key

            existing_grant = grants.get(grant_key)

            if existing_grant is None:
                grant = Grant(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    identity_id=grant_identity_id,
                    resource_id=grant_resource_id,
                    role_id=grant_role_id,
                    source_group_id=grant_source_group_id,
                    granted_via=granted_via,
                    permission_level=attrs.get("permission_level"),
                    source_connector_run_id=ctx.connector_run_id,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(grant)
                grants[grant_key] = grant
                changes.append(
                    EntityChange(
                        entity_type="grant",
                        entity_id=grant.id,
                        change_type=ChangeType.CREATED,
                    )
                )
            else:
                new_level = attrs.get("permission_level")
                old_level = existing_grant.permission_level
                revived = existing_grant.deleted_at is not None
                existing_grant.deleted_at = None
                existing_grant.last_seen_at = now
                existing_grant.source_connector_run_id = ctx.connector_run_id
                existing_grant.permission_level = new_level
                if revived:
                    changes.append(
                        EntityChange(
                            entity_type="grant",
                            entity_id=existing_grant.id,
                            change_type=ChangeType.CREATED,
                        )
                    )
                elif old_level != new_level:
                    changes.append(
                        EntityChange(
                            entity_type="grant",
                            entity_id=existing_grant.id,
                            change_type=ChangeType.UPDATED,
                            field_changes=[{"field": "permission_level", "old": old_level, "new": new_level}],
                        )
                    )

        elif obj.kind == "oauth_scope":
            attrs = obj.attributes
            oauth_app_id = ctx.id_maps["oauth_application"].get(attrs["oauth_application_ref"])
            if oauth_app_id is None:
                continue
            scope_name = attrs["scope_name"]
            collected_scopes.setdefault(oauth_app_id, set()).add(scope_name)
            scope_key = (oauth_app_id, scope_name)
            existing_scope = scope_rows.get(scope_key)
            if existing_scope is None:
                existing_scope = OAuthScope(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    oauth_application_id=oauth_app_id,
                    scope_name=scope_name,
                    is_sensitive=bool(attrs.get("is_sensitive", False)),
                )
                session.add(existing_scope)
                scope_rows[scope_key] = existing_scope
            else:
                existing_scope.is_sensitive = bool(attrs.get("is_sensitive", False))

        elif obj.kind == "oauth_grant":
            attrs = obj.attributes
            oauth_grant_key = _oauth_grant_key(attrs, ctx)
            if oauth_grant_key is None:
                _skip_unresolved(obj.kind)
                continue
            oauth_app_id, identity_id = oauth_grant_key
            granted_at = _parse_optional_datetime(attrs.get("granted_at")) or now
            last_used_at = _parse_optional_datetime(attrs.get("last_used_at"))
            existing_oauth_grant = oauth_grants.get(oauth_grant_key)
            if existing_oauth_grant is None:
                oauth_grant = OAuthGrant(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    oauth_application_id=oauth_app_id,
                    identity_id=identity_id,
                    granted_at=granted_at,
                    last_used_at=last_used_at,
                    source_connector_run_id=ctx.connector_run_id,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(oauth_grant)
                oauth_grants[oauth_grant_key] = oauth_grant
                changes.append(
                    EntityChange(
                        entity_type="oauth_grant",
                        entity_id=oauth_grant.id,
                        change_type=ChangeType.CREATED,
                    )
                )
            else:
                # granted_at/last_used_at move on their own as the provider
                # records usage; not a posture change worth an event.
                if existing_oauth_grant.deleted_at is not None:
                    changes.append(
                        EntityChange(
                            entity_type="oauth_grant",
                            entity_id=existing_oauth_grant.id,
                            change_type=ChangeType.CREATED,
                        )
                    )
                existing_oauth_grant.deleted_at = None
                existing_oauth_grant.granted_at = granted_at
                existing_oauth_grant.last_used_at = last_used_at
                existing_oauth_grant.last_seen_at = now
                existing_oauth_grant.source_connector_run_id = ctx.connector_run_id

    session.flush()

    changes.extend(_reconcile_oauth_scopes(session, previous_scopes, collected_scopes))
    return changes


def _resolve_identity_ids(session: Session, refs: set[str], ctx: UpsertContext) -> dict[str, uuid.UUID]:
    """Provider id -> identity id, from this run's id map first and the table second.

    An events-only incremental run (the audit-log poll) never collects the
    directory, so its id map has no identities; the accounts it names already
    exist from the last full sync and are looked up by provider id.
    """
    resolved = {ref: found for ref in refs if (found := ctx.id_maps["identity"].get(ref)) is not None}
    missing = refs - set(resolved)
    if missing:
        rows = session.execute(
            select(Identity.provider_object_id, Identity.id).where(
                Identity.application_instance_id == ctx.application_instance_id,
                _any_str(Identity.provider_object_id, missing),
            )
        ).all()
        resolved.update({str(provider_id): identity_id for provider_id, identity_id in rows})
    return resolved


def apply_identity_activity(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> int:
    """Fold this run's ``identity_activity`` observations onto ``identities``.

    One observation per account survives: the latest ``observed_at`` in the
    run, which is then merged with the stored value by ``merge_last_active``,
    so a cursor window that re-reads its 15-minute overlap is idempotent and a
    short window can only move the value forward. Returns the number of
    identities whose activity advanced.
    """
    latest: dict[str, tuple[datetime, str]] = {}
    for obj in objects:
        if obj.kind != IDENTITY_ACTIVITY_KIND:
            continue
        ref = obj.attributes.get("identity_ref")
        observed_at = _parse_optional_datetime(obj.attributes.get("observed_at"))
        if not ref or observed_at is None:
            continue
        source = str(obj.attributes.get("source") or "audit")
        current = latest.get(str(ref))
        if current is None or observed_at > current[0]:
            latest[str(ref)] = (observed_at, source)
    if not latest:
        return 0

    identity_ids = _resolve_identity_ids(session, set(latest), ctx)
    if not identity_ids:
        return 0
    by_id = {
        row.id: row for row in session.scalars(select(Identity).where(_any_uuid(Identity.id, identity_ids.values()))).all()
    }
    advanced = 0
    for ref, (observed_at, source) in latest.items():
        identity = by_id.get(identity_ids.get(ref))  # type: ignore[arg-type]
        if identity is None:
            continue
        merged_at, merged_source = merge_last_active(
            identity.last_active_at, identity.last_active_source, observed_at, source
        )
        if merged_at != identity.last_active_at or merged_source != identity.last_active_source:
            identity.last_active_at = merged_at
            identity.last_active_source = merged_source
            advanced += 1
    return advanced


def _apply_service_account_owners(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> None:
    """Write ``service_accounts.owner_identity_id`` for identities that name an owner.

    A non-human account's owner is the person to ask about it; a row with no
    known owner is the signal "service account without an owner" policies read.
    """
    owners: dict[str, str] = {
        obj.provider_id: str(ref)
        for obj in objects
        if obj.kind == "identity" and obj.attributes.get("identity_type") == "service_account"
        if (ref := obj.attributes.get("owner_identity_ref"))
    }
    if not owners:
        return
    resolved = _resolve_identity_ids(session, set(owners) | set(owners.values()), ctx)
    account_ids = {resolved[provider_id] for provider_id in owners if provider_id in resolved}
    if not account_ids:
        return
    existing = {
        row.identity_id: row
        for row in session.scalars(select(ServiceAccount).where(_any_uuid(ServiceAccount.identity_id, account_ids))).all()
    }
    for provider_id, owner_ref in owners.items():
        account_id = resolved.get(provider_id)
        if account_id is None:
            continue
        owner_id = resolved.get(owner_ref)
        row = existing.get(account_id)
        if row is None:
            session.add(ServiceAccount(identity_id=account_id, owner_identity_id=owner_id))
        else:
            row.owner_identity_id = owner_id


def _reconcile_oauth_scopes(
    session: Session,
    previous: dict[uuid.UUID, set[str]],
    collected: dict[uuid.UUID, set[str]],
) -> list[EntityChange]:
    """Drop scopes the provider no longer reports and emit the per-app scope diff.

    Stale scope rows have to go, or a revoked ``admin:org`` would keep matching
    over-scoped-app policies forever.
    """
    changes: list[EntityChange] = []
    for app_id, current in collected.items():
        before = previous.get(app_id, set())
        if before == current:
            continue

        removed = before - current
        if removed:
            session.execute(
                delete(OAuthScope).where(
                    OAuthScope.oauth_application_id == app_id,
                    OAuthScope.scope_name.in_(removed),
                )
            )

        changes.append(
            EntityChange(
                entity_type="oauth_application",
                entity_id=app_id,
                change_type=ChangeType.UPDATED,
                field_changes=[{"field": "scopes", "old": sorted(before), "new": sorted(current)}],
            )
        )
    return changes


def detect_deletions(session: Session, ctx: UpsertContext, run_started_at: datetime) -> list[EntityChange]:
    """Any row this connector wrote that the current run didn't touch (its
    last_seen_at predates the run) is a deletion: the row is tombstoned
    (``deleted_at``) rather than removed, and a DELETED change is emitted.
    Deduped against previously-recorded DELETED events so rows tombstoned
    before the column existed are not reported a second time.

    Covers relationship rows as well as entities: an admin losing a role and a
    user losing an OAuth grant are both disappearances, not attribute edits.

    Append-only kinds (activity ``event``) are excluded — historical audit
    rows are pruned by retention policy, not by collection absence.
    """
    changes: list[EntityChange] = []

    for kind, model in _MODEL_BY_KIND.items():
        if kind in APPEND_ONLY_KINDS:
            continue
        # Scoped to this *connector instance*, not just the application
        # instance: two instances may be bound to one tenant (a PAT and a
        # GitHub App on the same org) with different coverage, and each would
        # otherwise report the rows only the other one collects as deleted on
        # every run. A row both collect carries whichever run saw it last, so
        # it is tombstoned by the instance that last owned it once both stop
        # seeing it. The same join already scopes the relationship rows below.
        stale_rows = cast(
            "list[ProvenanceEntity]",
            list(
                session.scalars(
                    select(model)
                    .join(ConnectorRun, ConnectorRun.id == model.source_connector_run_id)
                    .where(
                        model.application_instance_id == ctx.application_instance_id,
                        ConnectorRun.connector_instance_id == ctx.connector_instance_id,
                        model.last_seen_at < run_started_at,
                        model.deleted_at.is_(None),
                    )
                ).all()
            ),
        )
        for row in stale_rows:
            row.deleted_at = run_started_at
        changes.extend(_undeleted_changes(session, ctx, kind, [row.id for row in stale_rows]))

    for kind, rel_model in _RELATIONSHIP_MODEL_BY_KIND.items():
        # Relationship rows have no application_instance_id of their own, so
        # they're scoped through the run that wrote them.
        stale_ids = list(
            session.scalars(
                select(rel_model.id)
                .join(ConnectorRun, ConnectorRun.id == rel_model.source_connector_run_id)
                .where(
                    rel_model.org_id == ctx.org_id,
                    ConnectorRun.connector_instance_id == ctx.connector_instance_id,
                    rel_model.last_seen_at < run_started_at,
                    rel_model.deleted_at.is_(None),
                )
            ).all()
        )
        if stale_ids:
            # One array bind parameter however many rows: a mass revocation of
            # more than 65k memberships otherwise fails at flush on psycopg's
            # parameter-count limit.
            session.execute(update(rel_model).where(_any_uuid(rel_model.id, stale_ids)).values(deleted_at=run_started_at))
        changes.extend(_undeleted_changes(session, ctx, kind, stale_ids))

    return changes


def _undeleted_changes(session: Session, ctx: UpsertContext, kind: str, entity_ids: list[uuid.UUID]) -> list[EntityChange]:
    """DELETED changes for the ids whose latest event is not already DELETED.

    Only the *latest* event counts: a grant that was revoked, restored (a
    CREATED event) and revoked again is a second revocation and must be
    reported. What this still dedupes is a row tombstoned before the
    ``deleted_at`` column existed, whose last word is already DELETED.
    """
    if not entity_ids:
        return []

    already_flagged: set[uuid.UUID] = set()
    for start in range(0, len(entity_ids), _IN_CHUNK):
        latest = session.execute(
            select(Event.entity_id, Event.change_type)
            .where(
                Event.org_id == ctx.org_id,
                Event.entity_type == kind,
                Event.entity_id.in_(entity_ids[start : start + _IN_CHUNK]),
            )
            .distinct(Event.entity_id)
            .order_by(Event.entity_id, Event.detected_at.desc())
        ).all()
        already_flagged.update(entity_id for entity_id, change_type in latest if change_type == ChangeType.DELETED)
    return [
        EntityChange(entity_type=kind, entity_id=entity_id, change_type=ChangeType.DELETED)
        for entity_id in entity_ids
        if entity_id not in already_flagged
    ]
