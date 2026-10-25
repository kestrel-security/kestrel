# Kestrel connector: Slack

Collects Slack workspace members, user groups, admin/owner roles, Enterprise
Grid org roles, installed OAuth apps, Slack Connect organizations, externally
shared channels, and curated Audit Logs into Kestrel's normalized model.

**Status:** live token sync is the production path. For Enterprise depth,
org-install an app as Org Owner and paste the **user** token. Workspace bot
tokens still sync members / groups / Owner-Admin flags. Fixtures remain for
CI and offline demos. Cursor pagination raises rather than silently truncating.
Test connection classifies auth / permission / rate-limit / network; optional
Enterprise probes do not fail core health.

## Why this connector exists

It is the third connector, and the **first to populate OAuth posture tables**
(`OAuthApplication`, `OAuthScope`, `OAuthGrant`). Slack's Admin Apps + Audit
Logs APIs are the natural source on **Enterprise Grid**.

Distinctive shapes:

- **Flag-derived admin roles.** Workspace `is_primary_owner` / `is_owner` /
  `is_admin` become synthetic privileged roles and grants.
- **Org system roles.** `admin.roles.listAssignments` overlays Grid roles
  (Org Admin, User Admin, …).
- **User groups** map cleanly to Kestrel groups / memberships.
- **Slack Connect** external orgs → `slack_connect_org_connected` setting; ext-shared
  channels → `resource` + sharing settings.
- **Audit Logs** → curated `event` rows (privilege, app scopes, guests,
  external sharing) — login noise dropped.

## Object types

The rows below are the `object_types` in `manifest.yaml` (25), with the entity
kind each one maps to. Everything past the workspace core needs Enterprise
Grid and an org-installed user token; those families are skipped and recorded,
never failed, on a workspace bot token.

| Object type | Maps to | Notes |
|---|---|---|
| `team` | setting | Tenant settings from `team.info` (domain, workspace name). |
| `user` | identity | `deleted` → `is_disabled`; bots → `service_account`; guests → `is_external`; `updated` → `last_active_at`. |
| `usergroup` | group | |
| `usergroup_member` | group_membership | |
| `admin_role` | role | Synthetic Primary Owner / Owner / Admin roles. |
| `role_assignment` | grant | Flag-derived assignments of those roles. |
| `oauth_app` | oauth_application | Grid Admin Apps (`admin.apps.approved.list`). |
| `oauth_scope` | oauth_scope | One per approved-app scope. |
| `oauth_grant` | oauth_grant | Installer grants derived from the approved-app record. |
| `workspace` | group | `admin.teams.list` plus `admin.teams.settings.info`. |
| `org_role` | role | Grid system roles (`admin.roles.listAssignments`). |
| `org_role_assignment` | grant | Assignments of those roles. |
| `restricted_app` | oauth_application | Apps restricted by org policy. |
| `app_request` | setting | Pending app-approval requests. |
| `external_team` | setting | Slack Connect orgs (`slack_connect_org_connected`). |
| `channel` | resource | Every public and private channel the token can see, with membership grants for private and externally shared channels up to `channel_membership_limit`. |
| `shared_channel` | resource | Ext-shared / Connect channels (`admin.conversations.search`). |
| `anomaly_allowlist` | setting | Enterprise anomaly IP/ASN allowlist. |
| `user_session_setting` | setting | Per-account session duration (`admin.users.session.getSettings`); accounts with no explicit setting get no row. |
| `audit_log` | event (incremental) | Curated Audit Logs, cursored from the previous run. |
| `sso_policy` | setting | SSO / email-password policy assignments (`admin.auth.policy.getEntities`): who may bypass SSO. |
| `information_barrier` | setting | Information barriers (`admin.barriers.list`). |
| `workflow` | resource | Workflow inventory (`admin.workflows.search`). |
| `channel_retention` | setting | Per-channel custom retention (`admin.conversations.getCustomRetention`). |
| `invite_request` | setting | Pending invite requests (`admin.invites.invited.list`). |

## Fixture mode

```bash
uv run kestrel connector validate connectors/slack
uv run pytest tests/unit/connectors -k slack -q
uv run kestrel pack validate packs/slack-posture
```

Fixtures describe synthetic `T0ACMEWORK` / `E0ACMEGRID`: primary owner with MFA
(Ada), dormant admin **without** MFA (Grace), unused Calendar OAuth install,
guest, deactivated user, bot, overscoped apps, Connect org, ext-shared channel,
pending app request, empty anomaly allowlist, and curated Audit Logs (plus
login noise that must be dropped).

## Live mode

Full setup: [`docs/connectors/slack-setup.md`](../../docs/connectors/slack-setup.md).
Enterprise sandbox cookbook:
[`docs/connectors/slack-setup.md`](../../docs/connectors/slack-setup.md#building-a-test-tenant).

**Token:** Kestrel stores one secret (`bot_token`). Enterprise Grid → paste
**User OAuth Token** (`xoxp` / `xoxe`) with member/admin/audit on **User Token
Scopes**. Also add **`team:read` under Bot Token Scopes** so Slack OAuth can
install (empty bot scopes → `no_bot_scopes_requested`); still paste the **user**
token into Kestrel. `conversations.connect:manage` is bot-only. Workspace-only
→ paste `xoxb` with bot scopes.

`build_live_transport` talks to `https://slack.com/api`. Audit Logs use
`https://api.slack.com/audit/v1` with the same Bearer token.

## Honest limits

- **No hosted Slack OAuth.** Paste token only.
- **Enterprise depth is Grid + org install.** Workspace-only tokens skip Admin
  Apps / org roles / Audit Logs / Connect with classified health messages.
- **`last_used_at` is often unknown live.** Unused-app policy keys off an
  explicit fixture field and will not false-positive every live app.
- **Events are curated, not a SIEM dump.** Unmapped Audit actions (including
  logins) are dropped.
- **No write-back.** Read-only scopes only.
- **Out of scope:** Discovery, SCIM catalog, message content, **DLP / export**
  policies (Enterprise APIs vary by plan). Channel inventory and per-channel
  custom retention *are* collected (`channel`, `channel_retention`).
- **`admin.apps.activities.list`** is collected for fixture-backed unused-app
  signal; live `last_used_at` remains sparse on many workspaces.
- **Workspace-wide 2FA enforcement and app-approval policy** are not exposed
  by any Slack method. SSO comes from the policy assignment list
  (`sso_policy`, `admin.auth.policy:read`), not a workspace flag, and session
  duration is per account (`user_session_setting`). Below Enterprise Grid many
  controls do not exist — encoded as capability keys so coverage shows "not
  available on this plan" instead of a silent pass.

## Collection gaps (honest)

See [`docs/posture-baselines/slack.md`](../../docs/posture-baselines/slack.md).
Capability keys on `manifest.yaml` (`provides_capabilities`) drive pack coverage.
