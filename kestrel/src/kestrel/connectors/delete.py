# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Delete a connector instance and its application inventory.

Order matters: normalized entities and graph rows reference
``connector_runs`` / ``application_instances`` without ON DELETE CASCADE, so
dependents are torn down before the runs, the instance, and the application
instance.

There is deliberately no "keep the inventory" mode. Every provenance entity
and relationship row carries a NOT NULL ``source_connector_run_id``, and
``connector_runs.connector_instance_id`` is NOT NULL too, so inventory cannot
outlive the instance whose runs produced it without a schema change.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from kestrel.db.models.access import Grant, Group, GroupMembership, Permission, Role, RolePermission
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.connector import ConnectorCursor, ConnectorInstance, ConnectorRun, ConnectorSecret
from kestrel.db.models.event import Event
from kestrel.db.models.finding import Finding
from kestrel.db.models.graph_edge import GraphEdge, GraphNode
from kestrel.db.models.identity import ExternalIdentity, Identity, ServiceAccount, User
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.policy import PolicyEvaluation
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.findings.purge import purge_findings
from kestrel.graph.snapshots import GraphSnapshot

# Tables this module removes rows from. (``applications`` too, when no other
# application instance uses it, but only ``application_instances`` references
# that table.)
DELETED_TABLES = frozenset({"connector_instances", "connector_runs", "application_instances"})

# Every (table, column) foreign key into DELETED_TABLES. Each is deleted or
# nulled by ``delete_connector_instance`` before its parent row goes.
# ``tests/unit/core/test_connector_delete_references.py`` checks this against
# the SQLAlchemy metadata so a new referencing table cannot be missed.
CLEARED_REFERENCES = frozenset(
    {
        ("connector_cursors", "connector_instance_id"),
        ("connector_secrets", "connector_instance_id"),
        ("connector_runs", "connector_instance_id"),
        ("connector_instances", "application_instance_id"),
        ("events", "connector_run_id"),
        ("graph_snapshots", "connector_run_id"),
        ("graph_snapshots", "application_instance_id"),
        ("graph_edges", "source_connector_run_id"),
        ("policy_evaluations", "connector_run_id"),
        ("grants", "source_connector_run_id"),
        ("group_memberships", "source_connector_run_id"),
        ("oauth_grants", "source_connector_run_id"),
        ("activity_events", "source_connector_run_id"),
        ("activity_events", "application_instance_id"),
        ("identities", "source_connector_run_id"),
        ("identities", "application_instance_id"),
        ("groups", "source_connector_run_id"),
        ("groups", "application_instance_id"),
        ("roles", "source_connector_run_id"),
        ("roles", "application_instance_id"),
        ("permissions", "source_connector_run_id"),
        ("permissions", "application_instance_id"),
        ("resources", "source_connector_run_id"),
        ("resources", "application_instance_id"),
        ("oauth_applications", "source_connector_run_id"),
        ("oauth_applications", "application_instance_id"),
        ("tenant_settings", "source_connector_run_id"),
        ("tenant_settings", "application_instance_id"),
    }
)


class ConnectorDeleteError(ValueError):
    """Raised when delete cannot proceed. Callers map this to HTTP 4xx."""


def delete_connector_instance(
    session: Session,
    *,
    org_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
) -> dict[str, object]:
    """Remove a connector instance with its secrets, cursors, runs, and inventory.

    Deletes every entity, relationship, graph row, snapshot, change event and
    finding collected for the bound ``ApplicationInstance``. The application
    instance itself (and its ``Application``, if nothing else uses it) goes
    too, unless another connector instance is still bound to it. The global
    ``connectors`` catalog row is never deleted (it comes from installed
    packages). Does not commit.
    """
    instance = session.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org_id:
        raise ConnectorDeleteError("Connector instance not found")

    app_instance_id = instance.application_instance_id
    run_ids = list(session.scalars(select(ConnectorRun.id).where(ConnectorRun.connector_instance_id == instance.id)).all())

    summary: dict[str, object] = {
        "connector_instance_id": str(instance.id),
        "application_instance_id": str(app_instance_id),
        "runs_deleted": len(run_ids),
    }

    _purge_application_inventory(session, org_id=org_id, application_instance_id=app_instance_id)

    session.execute(delete(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id))
    session.execute(delete(ConnectorCursor).where(ConnectorCursor.connector_instance_id == instance.id))
    if run_ids:
        # Evaluation history belongs to the policy, not the run; keep it.
        session.execute(
            update(PolicyEvaluation).where(PolicyEvaluation.connector_run_id.in_(run_ids)).values(connector_run_id=None)
        )
        # Edges outside this app's inventory (identity-link edges, say) can
        # still name one of these runs as their source.
        session.execute(
            update(GraphEdge).where(GraphEdge.source_connector_run_id.in_(run_ids)).values(source_connector_run_id=None)
        )
        session.execute(delete(Event).where(Event.connector_run_id.in_(run_ids)))
        session.execute(delete(GraphSnapshot).where(GraphSnapshot.connector_run_id.in_(run_ids)))
        # Relationship rows have no application_instance_id of their own. The
        # entity-based purge catches nearly all of them; this catches the rest.
        session.execute(delete(Grant).where(Grant.source_connector_run_id.in_(run_ids)))
        session.execute(delete(GroupMembership).where(GroupMembership.source_connector_run_id.in_(run_ids)))
        session.execute(delete(OAuthGrant).where(OAuthGrant.source_connector_run_id.in_(run_ids)))
        session.execute(delete(ConnectorRun).where(ConnectorRun.id.in_(run_ids)))

    session.delete(instance)
    session.flush()

    remaining = session.scalars(
        select(ConnectorInstance.id).where(ConnectorInstance.application_instance_id == app_instance_id)
    ).first()
    if remaining is not None:
        summary["application_instance_deleted"] = False
        return summary

    app_instance = session.get(ApplicationInstance, app_instance_id)
    application_id = app_instance.application_id if app_instance else None
    if app_instance is not None:
        session.execute(delete(GraphSnapshot).where(GraphSnapshot.application_instance_id == app_instance_id))
        session.delete(app_instance)
        session.flush()
    if application_id is not None:
        other = session.scalars(
            select(ApplicationInstance.id).where(ApplicationInstance.application_id == application_id)
        ).first()
        if other is None:
            application = session.get(Application, application_id)
            if application is not None:
                session.delete(application)
                session.flush()
    summary["application_instance_deleted"] = True
    return summary


def _purge_application_inventory(session: Session, *, org_id: uuid.UUID, application_instance_id: uuid.UUID) -> None:
    """Delete normalized entities, graph, and related findings for one app instance."""
    identity_ids = list(
        session.scalars(select(Identity.id).where(Identity.application_instance_id == application_instance_id)).all()
    )
    group_ids = list(session.scalars(select(Group.id).where(Group.application_instance_id == application_instance_id)).all())
    role_ids = list(session.scalars(select(Role.id).where(Role.application_instance_id == application_instance_id)).all())
    permission_ids = list(
        session.scalars(select(Permission.id).where(Permission.application_instance_id == application_instance_id)).all()
    )
    resource_ids = list(
        session.scalars(select(Resource.id).where(Resource.application_instance_id == application_instance_id)).all()
    )
    oauth_app_ids = list(
        session.scalars(
            select(OAuthApplication.id).where(OAuthApplication.application_instance_id == application_instance_id)
        ).all()
    )
    setting_ids = list(
        session.scalars(
            select(TenantSetting.id).where(TenantSetting.application_instance_id == application_instance_id)
        ).all()
    )

    subject_ids = set(identity_ids + resource_ids + oauth_app_ids + setting_ids)
    subject_ids.add(application_instance_id)

    finding_ids: list[uuid.UUID] = []
    if subject_ids:
        finding_ids = list(
            session.scalars(
                select(Finding.id).where(
                    Finding.org_id == org_id,
                    Finding.subject_id.in_(subject_ids),
                )
            ).all()
        )

    purge_findings(session, finding_ids)

    # Graph: remove edges touching nodes for this app's entities, then nodes.
    entity_ids = set(identity_ids + group_ids + role_ids + permission_ids + resource_ids + oauth_app_ids)
    entity_ids.add(application_instance_id)
    node_ids: list[uuid.UUID] = []
    if entity_ids:
        node_ids = list(
            session.scalars(
                select(GraphNode.id).where(
                    GraphNode.org_id == org_id,
                    GraphNode.object_id.in_(entity_ids),
                )
            ).all()
        )
    if node_ids:
        session.execute(
            delete(GraphEdge).where((GraphEdge.source_node_id.in_(node_ids)) | (GraphEdge.target_node_id.in_(node_ids)))
        )
        session.execute(delete(GraphNode).where(GraphNode.id.in_(node_ids)))

    if group_ids and identity_ids:
        session.execute(
            delete(GroupMembership).where(
                (GroupMembership.group_id.in_(group_ids)) | (GroupMembership.identity_id.in_(identity_ids))
            )
        )
    elif group_ids:
        session.execute(delete(GroupMembership).where(GroupMembership.group_id.in_(group_ids)))
    elif identity_ids:
        session.execute(delete(GroupMembership).where(GroupMembership.identity_id.in_(identity_ids)))

    if role_ids or permission_ids:
        conds = []
        if role_ids:
            conds.append(RolePermission.role_id.in_(role_ids))
        if permission_ids:
            conds.append(RolePermission.permission_id.in_(permission_ids))
        session.execute(delete(RolePermission).where(or_(*conds)))

    # Grants reference identities/groups/roles/resources/permissions.
    grant_filters = []
    if identity_ids:
        grant_filters.append(Grant.identity_id.in_(identity_ids))
    if role_ids:
        grant_filters.append(Grant.role_id.in_(role_ids))
    if permission_ids:
        grant_filters.append(Grant.permission_id.in_(permission_ids))
    if resource_ids:
        grant_filters.append(Grant.resource_id.in_(resource_ids))
    if group_ids:
        grant_filters.append(Grant.source_group_id.in_(group_ids))
    if grant_filters:
        session.execute(delete(Grant).where(or_(*grant_filters)))

    oauth_grant_filters = []
    if oauth_app_ids:
        oauth_grant_filters.append(OAuthGrant.oauth_application_id.in_(oauth_app_ids))
    if identity_ids:
        oauth_grant_filters.append(OAuthGrant.identity_id.in_(identity_ids))
    if oauth_grant_filters:
        session.execute(delete(OAuthGrant).where(or_(*oauth_grant_filters)))
    if oauth_app_ids:
        session.execute(delete(OAuthScope).where(OAuthScope.oauth_application_id.in_(oauth_app_ids)))
        # Clear owner FK before deleting identities / apps.
        session.execute(
            update(OAuthApplication).where(OAuthApplication.id.in_(oauth_app_ids)).values(owner_identity_id=None)
        )

    if identity_ids:
        session.execute(
            update(ServiceAccount).where(ServiceAccount.owner_identity_id.in_(identity_ids)).values(owner_identity_id=None)
        )
        session.execute(delete(User).where(User.identity_id.in_(identity_ids)))
        session.execute(delete(ServiceAccount).where(ServiceAccount.identity_id.in_(identity_ids)))
        session.execute(delete(ExternalIdentity).where(ExternalIdentity.identity_id.in_(identity_ids)))
        session.execute(delete(Identity).where(Identity.id.in_(identity_ids)))

    if oauth_app_ids:
        session.execute(delete(OAuthApplication).where(OAuthApplication.id.in_(oauth_app_ids)))

    if group_ids:
        session.execute(delete(Group).where(Group.id.in_(group_ids)))
    if role_ids:
        session.execute(delete(Role).where(Role.id.in_(role_ids)))
    if permission_ids:
        session.execute(delete(Permission).where(Permission.id.in_(permission_ids)))
    if resource_ids:
        session.execute(delete(Resource).where(Resource.id.in_(resource_ids)))

    session.execute(delete(ActivityEvent).where(ActivityEvent.application_instance_id == application_instance_id))
    session.execute(delete(TenantSetting).where(TenantSetting.application_instance_id == application_instance_id))
    session.flush()
