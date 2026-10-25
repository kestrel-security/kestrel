# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Teardown for the fixture-backed demo tenants.

Why this is a full cascade rather than "just remove the connector":

``connector_runs.connector_instance_id`` is NOT NULL, so a connector instance
cannot be deleted while any of its runs survive. And **fifteen** tables carry a
NOT NULL ``source_connector_run_id`` / ``connector_run_id`` back to those runs --
every provenance entity, every relationship row, activity events, graph
snapshots, and the ``events`` change feed. So a run cannot be deleted while any
of the inventory it produced survives either.

The previous implementation deleted runs and then the instance while leaving
inventory in place, which is why it failed with::

    ForeignKeyViolation: update or delete on table "connector_instances"
    violates foreign key constraint "connector_runs_connector_instance_id_fkey"

There is no partial mode to recover here: the schema makes "remove the connector
but keep its data" unrepresentable. Teardown removes the tenant and everything
derived from it, in dependency order.

Scoping is by the demo tenants' own rows throughout -- an org that also has real
connectors keeps them, including their findings.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from kestrel.db.models.access import Grant, Group, GroupMembership, Permission, Role, RolePermission
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorCursor, ConnectorInstance, ConnectorRun, ConnectorSecret
from kestrel.db.models.event import Event
from kestrel.db.models.finding import Exception_, Finding, FindingEvidence
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.graph_edge import GraphEdge, GraphNode
from kestrel.db.models.identity import ExternalIdentity, Identity, ServiceAccount, User
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.policy import PolicyEvaluation
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.db.models.ticket import FindingTicket
from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus
from kestrel.graph.snapshots import GraphSnapshot

# Provenance-tracked entity models, each scoped by application_instance_id.
_PROVENANCE_MODELS = (
    Identity,
    Group,
    Role,
    Permission,
    Resource,
    OAuthApplication,
    TenantSetting,
    ActivityEvent,
)

# Deletion order within the provenance set. These tables reference each other:
# `oauth_applications.owner_identity_id` points at `identities`, so the apps have
# to go first. Everything else is independent, but the order is spelled out
# rather than inferred so a future cross-reference fails loudly in review rather
# than at teardown time.
_PROVENANCE_DELETE_ORDER = (
    OAuthApplication,
    Group,
    Role,
    Permission,
    Resource,
    TenantSetting,
    ActivityEvent,
    Identity,
)


@dataclass
class TeardownResult:
    """Row counts removed, keyed by table name, plus the tenants affected."""

    application_instances: int = 0
    connector_instances: int = 0
    deleted: dict[str, int] = field(default_factory=dict)

    def record(self, table: str, count: int) -> None:
        if count:
            self.deleted[table] = self.deleted.get(table, 0) + count

    @property
    def total_rows(self) -> int:
        return sum(self.deleted.values())


def _ids(session: Session, stmt) -> list[uuid.UUID]:
    return list(session.scalars(stmt).all())


def _delete_where(session: Session, result: TeardownResult, model, *criteria) -> None:
    """Bulk-delete and record the count. No-ops on an empty criteria match."""
    if not criteria:
        return
    outcome = session.execute(delete(model).where(*criteria))
    result.record(model.__tablename__, getattr(outcome, "rowcount", 0) or 0)


def teardown_application_instances(
    session: Session,
    *,
    org_id: uuid.UUID,
    application_instance_ids: list[uuid.UUID],
) -> TeardownResult:
    """Delete the given tenants and everything derived from them.

    Does not commit -- the caller owns the transaction.
    """
    result = TeardownResult()
    if not application_instance_ids:
        return result

    app_ids = application_instance_ids
    result.application_instances = len(app_ids)

    connector_instance_ids = _ids(
        session,
        select(ConnectorInstance.id).where(
            ConnectorInstance.org_id == org_id,
            ConnectorInstance.application_instance_id.in_(app_ids),
        ),
    )
    result.connector_instances = len(connector_instance_ids)

    run_ids = (
        _ids(
            session,
            select(ConnectorRun.id).where(ConnectorRun.connector_instance_id.in_(connector_instance_ids)),
        )
        if connector_instance_ids
        else []
    )

    # Entity ids per kind, collected before anything is deleted -- findings are
    # keyed by subject_id, which is a bare UUID with no FK, so the only way to
    # scope them to this tenant is to know which subjects are going away.
    entity_ids: dict[type, list[uuid.UUID]] = {
        entity: _ids(
            session,
            select(entity.id).where(entity.application_instance_id.in_(app_ids)),
        )
        for entity in _PROVENANCE_MODELS
    }
    subject_ids = [row_id for ids in entity_ids.values() for row_id in ids] + app_ids

    # -- findings and everything hanging off them ------------------------
    finding_ids = _ids(
        session,
        select(Finding.id).where(Finding.org_id == org_id, Finding.subject_id.in_(subject_ids)),
    )
    if finding_ids:
        for child in (
            FindingEvidence,
            FindingNote,
            FindingWatcher,
            FindingTicket,
            Exception_,
            OperatorInAppNotification,
        ):
            _delete_where(session, result, child, child.finding_id.in_(finding_ids))
        # Webhook deliveries reference findings but belong to the webhook
        # subsystem; null the link rather than deleting delivery history. A
        # delivery still pending for a finding that is going away will never
        # mean anything, so it goes rather than sitting in the backlog.
        _delete_where(
            session,
            result,
            WebhookDelivery,
            WebhookDelivery.finding_id.in_(finding_ids),
            WebhookDelivery.status == WebhookDeliveryStatus.PENDING,
        )
        session.execute(update(WebhookDelivery).where(WebhookDelivery.finding_id.in_(finding_ids)).values(finding_id=None))
        _delete_where(session, result, Finding, Finding.id.in_(finding_ids))

    if run_ids:
        _delete_where(session, result, PolicyEvaluation, PolicyEvaluation.connector_run_id.in_(run_ids))
        _delete_where(session, result, Event, Event.connector_run_id.in_(run_ids))
        _delete_where(session, result, GraphSnapshot, GraphSnapshot.connector_run_id.in_(run_ids))

    # -- graph read-model -------------------------------------------------
    node_ids = _ids(
        session,
        select(GraphNode.id).where(GraphNode.org_id == org_id, GraphNode.object_id.in_(subject_ids)),
    )
    if node_ids:
        _delete_where(
            session,
            result,
            GraphEdge,
            (GraphEdge.source_node_id.in_(node_ids)) | (GraphEdge.target_node_id.in_(node_ids)),
        )
        _delete_where(session, result, GraphNode, GraphNode.id.in_(node_ids))

    # -- relationship + detail rows referencing entities ------------------
    identity_ids = entity_ids[Identity]
    group_ids = entity_ids[Group]
    role_ids = entity_ids[Role]
    resource_ids = entity_ids[Resource]
    oauth_app_ids = entity_ids[OAuthApplication]

    if identity_ids:
        for detail in (User, ServiceAccount, ExternalIdentity):
            _delete_where(session, result, detail, detail.identity_id.in_(identity_ids))

    if oauth_app_ids:
        _delete_where(session, result, OAuthScope, OAuthScope.oauth_application_id.in_(oauth_app_ids))
        _delete_where(session, result, OAuthGrant, OAuthGrant.oauth_application_id.in_(oauth_app_ids))
    if identity_ids:
        _delete_where(session, result, OAuthGrant, OAuthGrant.identity_id.in_(identity_ids))
        _delete_where(session, result, GroupMembership, GroupMembership.identity_id.in_(identity_ids))
        _delete_where(session, result, Grant, Grant.identity_id.in_(identity_ids))
    if group_ids:
        _delete_where(session, result, GroupMembership, GroupMembership.group_id.in_(group_ids))
        _delete_where(session, result, Grant, Grant.source_group_id.in_(group_ids))
    if role_ids:
        _delete_where(session, result, RolePermission, RolePermission.role_id.in_(role_ids))
        _delete_where(session, result, Grant, Grant.role_id.in_(role_ids))
    if resource_ids:
        _delete_where(session, result, Grant, Grant.resource_id.in_(resource_ids))
    if run_ids:
        # Relationship rows have no application_instance_id of their own.
        _delete_where(session, result, Grant, Grant.source_connector_run_id.in_(run_ids))
        _delete_where(session, result, GroupMembership, GroupMembership.source_connector_run_id.in_(run_ids))
        _delete_where(session, result, OAuthGrant, OAuthGrant.source_connector_run_id.in_(run_ids))
        _delete_where(session, result, GraphEdge, GraphEdge.source_connector_run_id.in_(run_ids))

    _delete_where(session, result, GraphSnapshot, GraphSnapshot.application_instance_id.in_(app_ids))

    # -- entities, then runs, then the tenant itself ----------------------
    for entity in _PROVENANCE_DELETE_ORDER:
        _delete_where(session, result, entity, entity.application_instance_id.in_(app_ids))

    if connector_instance_ids:
        _delete_where(session, result, ConnectorRun, ConnectorRun.connector_instance_id.in_(connector_instance_ids))
        _delete_where(
            session,
            result,
            ConnectorSecret,
            ConnectorSecret.connector_instance_id.in_(connector_instance_ids),
        )
        _delete_where(
            session,
            result,
            ConnectorCursor,
            ConnectorCursor.connector_instance_id.in_(connector_instance_ids),
        )
        _delete_where(session, result, ConnectorInstance, ConnectorInstance.id.in_(connector_instance_ids))

    _delete_where(session, result, ApplicationInstance, ApplicationInstance.id.in_(app_ids))

    session.flush()
    return result
