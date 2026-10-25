# Domain model

The SQLAlchemy models in `kestrel/src/kestrel/db/models/`, one module per
domain group, and how they relate. Every tenant-owned table carries `org_id`
([ADR-0006](adr/0006-multi-tenancy-approach.md)). Migrations live in
`migrations/versions/` and are additive.

## Tenancy and operators

| Model | Module | Role |
|-------|--------|------|
| `Organization` | `org.py` | The single tenant in a default deployment; every other row hangs off it |
| `Operator`, `OperatorSession`, `ApiToken` | `operator.py` | People who log into Kestrel: email/password with Argon2id, role (`read_only` / `analyst` / `admin`), opaque browser sessions and long-lived API tokens ([ADR-0008](adr/0008-opaque-tokens-for-operator-auth.md)); `ui_preferences` JSON holds per-operator layout |
| `AuditLog` | `audit.py` | User-attributed audit trail for sensitive mutations (finding status and assignment, exceptions, connector instance create and sync, operator management, login/logout); `GET /audit-log`, `kestrel audit list` |
| `OperatorNotificationPreferences` | `notification_prefs.py` | Per-operator channel mutes and severity thresholds |
| `OperatorInAppNotification` | `in_app_notification.py` | Per-operator inbox rows written by `notifications/dispatch.py`; `GET /notifications` |
| `OrgLlmSettings` | `llm_settings.py` | Org-scoped LLM provider, model, and envelope-encrypted key for policy drafts |

## Applications and connectors

| Model | Module | Role |
|-------|--------|------|
| `Application`, `ApplicationInstance` | `application.py` | Catalog entry (`ApplicationType`: github, okta, google_workspace, slack, custom; `microsoft_365` is retained for rows written before that connector was removed) and a connected tenant of it |
| `Connector`, `ConnectorInstance`, `ConnectorSecret`, `ConnectorRun` | `connector.py` | Connector catalog (`ConnectorSource` builtin / custom), instance config with `AuthMethod`, `SyncMode` (fixtures / live) and `schedule_cron`, envelope-encrypted secrets ([ADR-0004](adr/0004-secrets-storage-and-encryption.md)), and run history with `ConnectorRunStatus` and trigger |

## Inventory (normalized entities)

Every normalized entity carries the `ProvenanceMixin` fields from
`kestrel/src/kestrel/db/base.py`: a stable id, `provider_object_id`, the
application instance and org, `first_seen_at` / `last_seen_at`, the connector
run that produced it, the untouched provider payload as `raw_source`, and a
`schema_version`.

| Model | Module | Role |
|-------|--------|------|
| `Identity` with `User`, `ServiceAccount`, `ExternalIdentity` | `identity.py` | Human and non-human accounts per application instance; `IdentityType`, `EmploymentStatus`, `mfa_enabled`, `is_external`, `is_disabled`, `last_active_at` |
| `Group`, `GroupMembership` | `access.py` | Groups and membership with an optional `membership_role` |
| `Role`, `Permission`, `RolePermission`, `Grant` | `access.py` | Roles (`is_privileged`), permissions, and grants to an identity or a group (`identity_id` nullable) with `permission_level` and `GrantedVia` |
| `Resource` | `resource.py` | Repositories, channels, shared drives, SharePoint sites, and `ResourceType.custom`; `ResourceVisibility` |
| `OAuthApplication`, `OAuthScope`, `OAuthGrant` | `oauth.py` | Third-party and installed apps, scopes with `is_sensitive`, and consent grants |
| `TenantSetting` | `setting.py` | Application-level configuration and posture settings with a `category` (`security`, `sharing`, `access`, …) |
| `ActivityEvent` | `activity_event.py` | Provider audit rows (`action`, `occurred_at`, `raw_source`) for `RESOURCE_TYPE=event` policies and finding provenance; capped per instance at 90 days and 50 000 rows by `kestrel.activity.retention` after each sync |

## Graph and change detection

| Model | Module | Role |
|-------|--------|------|
| `GraphNode`, `GraphEdge` | `graph_edge.py` | The derived access graph: `GraphNodeType`, `GraphEdgeType`, `AccessPath` ([`identity-graph.md`](identity-graph.md)) |
| `IdentityLink` | `identity_link.py` | Materialized cross-connector correlation: accounts in different application instances that belong to one person, drawn as federated edges and read by the Identities pages |
| `Event` | `event.py` | Sync-diff rows (`ChangeType` created / updated / deleted) with field-level before/after; the source of the Changes feed ([`changes.md`](changes.md)). Hashed per-run graph snapshots live in `graph_snapshots` (model in `kestrel/src/kestrel/graph/snapshots.py`) |

## Policies and findings

| Model | Module | Role |
|-------|--------|------|
| `Policy`, `PolicyVersion`, `PolicyEvaluation` | `policy.py` | Installed policies (`PolicySource` pack / custom / system), immutable versions with `Severity`, remediation, and compliance mappings, and evaluation runs with `PolicyEvaluationStatus` |
| `ComplianceControl`, `PolicyControlMapping` | `compliance.py` | Framework controls (`ComplianceFramework`: CIS, NIST CSF, SOC 2, CISA) and policy → control mappings from packs |
| `Finding`, `FindingEvidence`, `Exception_` | `finding.py` | Detections with `FindingStatus`, `FindingSubjectType` (identity, grant, setting, OAuth application, application, event, …), assignment, mute expiry; evidence rows; accepted-risk exceptions |
| `FindingNote`, `FindingWatcher`, `FindingFilterPreset` | `finding_note.py`, `finding_watcher.py`, `finding_preset.py` | Investigation notes, per-operator watches, saved search presets |
| `PostureTrendSnapshot` | `posture_trend.py` | One row per org per UTC day of open-by-severity and labeled factor counts, read by the dashboard trend widget. Written hourly by the `kestrel.posture.capture_daily_snapshot` beat task (idempotent per UTC day), and by the demo seed |

## Outbound integrations

| Model | Module | Role |
|-------|--------|------|
| `WebhookEndpoint`, `WebhookDelivery` | `webhook.py` | HMAC-signed finding lifecycle webhooks and delivery attempts with `WebhookDeliveryStatus` |
| `TicketIntegration`, `FindingTicket` | `ticket.py` | GitHub Issues / Jira Cloud integrations and the tickets created from findings |

## Dashboards

| Model | Module | Role |
|-------|--------|------|
| `Dashboard`, `DashboardWidget`, `DashboardSchedule`, `DashboardExport` | `dashboard.py` | Org boards (`DashboardVisibility`), widgets with a `query_spec` and `DashboardVizType`, email schedules (`DashboardScheduleFormat`), and an export audit ([`dashboards.md`](dashboards.md)) |

## Modeling rules

- Prefer additive columns and tables with Alembic migrations; irreversible migrations need explicit approval.
- Keep the graph derived; never make it the source of truth.
- Preserve `raw_source` for evidence and re-normalization; trim it with `kestrel retention trim-raw-source` on a retention window ([`operations/data-retention.md`](operations/data-retention.md)).
- Scope every query by `org_id`.
