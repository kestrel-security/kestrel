# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Importing this module registers every entity table on Base.metadata --
required before calling create_all() or running an Alembic autogenerate."""

from kestrel.db.models.access import (
    Grant,
    GrantedVia,
    Group,
    GroupMembership,
    Permission,
    Role,
    RolePermission,
)
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import (
    Application,
    ApplicationInstance,
    ApplicationInstanceStatus,
    ApplicationType,
)
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    MappingSource,
    PolicyControlMapping,
)
from kestrel.db.models.connector import (
    AuthMethod,
    Connector,
    ConnectorInstance,
    ConnectorRun,
    ConnectorRunStatus,
    ConnectorRunTrigger,
    ConnectorSecret,
    ConnectorSource,
    SyncMode,
)
from kestrel.db.models.dashboard import (
    Dashboard,
    DashboardExport,
    DashboardSchedule,
    DashboardScheduleFormat,
    DashboardVisibility,
    DashboardVizType,
    DashboardWidget,
)
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.finding import (
    Exception_,
    Finding,
    FindingEvidence,
    FindingStatus,
    FindingSubjectType,
)
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_preset import FindingFilterPreset
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.graph_edge import (
    AccessPath,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)
from kestrel.db.models.identity import (
    EmploymentStatus,
    ExternalIdentity,
    Identity,
    IdentityType,
    ServiceAccount,
    User,
)
from kestrel.db.models.identity_link import IdentityLink
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.llm_settings import OrgLlmSettings
from kestrel.db.models.notification_prefs import OperatorNotificationPreferences
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.operator import ApiToken, Operator, OperatorMfaRecoveryCode, OperatorRole, OperatorSession
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.db.models.resource import Resource, ResourceType, ResourceVisibility
from kestrel.db.models.setting import TenantSetting
from kestrel.db.models.smtp_settings import OrgSmtpSettings
from kestrel.db.models.ticket import FindingTicket, TicketIntegration
from kestrel.db.models.webhook import (
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
)
from kestrel.graph.snapshots import GraphSnapshot

__all__ = [
    "AccessPath",
    "ActivityEvent",
    "ApiToken",
    "Application",
    "ApplicationInstance",
    "ApplicationInstanceStatus",
    "ApplicationType",
    "AuditLog",
    "AuthMethod",
    "ChangeType",
    "ComplianceControl",
    "ComplianceFramework",
    "Connector",
    "ConnectorInstance",
    "ConnectorRun",
    "ConnectorRunStatus",
    "ConnectorRunTrigger",
    "ConnectorSecret",
    "ConnectorSource",
    "Dashboard",
    "DashboardExport",
    "DashboardSchedule",
    "DashboardScheduleFormat",
    "DashboardVisibility",
    "DashboardVizType",
    "DashboardWidget",
    "EmploymentStatus",
    "Event",
    "Exception_",
    "ExternalIdentity",
    "Finding",
    "FindingEvidence",
    "FindingFilterPreset",
    "FindingNote",
    "FindingStatus",
    "FindingSubjectType",
    "FindingTicket",
    "FindingWatcher",
    "Grant",
    "GrantedVia",
    "GraphEdge",
    "GraphEdgeType",
    "GraphNode",
    "GraphNodeType",
    "GraphSnapshot",
    "Group",
    "GroupMembership",
    "Identity",
    "IdentityLink",
    "IdentityType",
    "MappingSource",
    "OAuthApplication",
    "OAuthGrant",
    "OAuthScope",
    "Operator",
    "OperatorInAppNotification",
    "OperatorMfaRecoveryCode",
    "OperatorNotificationPreferences",
    "OperatorRole",
    "OperatorSession",
    "OrgLlmSettings",
    "OrgSmtpSettings",
    "Organization",
    "Permission",
    "Policy",
    "PolicyControlMapping",
    "PolicyEvaluation",
    "PolicyEvaluationStatus",
    "PolicySource",
    "PolicyVersion",
    "PostureTrendSnapshot",
    "Resource",
    "ResourceType",
    "ResourceVisibility",
    "Role",
    "RolePermission",
    "ServiceAccount",
    "Severity",
    "SyncMode",
    "TenantSetting",
    "TicketIntegration",
    "User",
    "WebhookDelivery",
    "WebhookDeliveryStatus",
    "WebhookEndpoint",
]
