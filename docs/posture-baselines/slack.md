# Slack posture baseline matrix

**Vendor baseline:** Slack Enterprise Grid security guidance (no official CIS/CISA baseline)  
**Framework mapping:** NIST CSF 1.1, CIS Controls v8.1 (organizational, not Slack-specific)

Profile levels: **L1** = essential workspace hardening, **L2** = Enterprise Grid depth, **mon** = activity monitor

## Section 1 — Authentication

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| CIS 6.3 | Workspace 2FA required | L1 | workspace 2FA policy | not-collectable | — | high |
| CIS 6.3 | Privileged roles without 2FA | L1 | identity roles + mfa_enabled | collected | `slack-privileged-without-mfa` | high |
| CIS 6.3 | Guest without 2FA | L1 | identity.is_external + mfa | collected | `slack-external-without-mfa` | medium |
| NIST PR.AC-7 | SAML SSO enforced | L1 | `admin.auth.policy.getEntities` → `sso_bypass_count` | collected | `slack-sso-not-enforced` | high |
| NIST PR.AC-7 | Session duration ≤12 hours | L2 | `admin.users.session.getSettings` → per-account `session_duration_hours` | collected | `slack-session-duration-excessive` | medium |
| NIST PR.AC-1 | Guest accounts without expiration | L1 | `expiration_ts` on user record | collected | `slack-guest-no-expiration` | medium |
| NIST PR.AC-1 | Stale invite requests (>30d) | L2 | `admin.invites.invited.list` → `days_pending` | collected | `slack-stale-invite-request` | low |

## Section 2 — Privileged access

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| CIS 6.8 | Deactivated user retains Owner/Admin | L1 | identity.is_disabled + roles | collected | `slack-disabled-privileged` | critical |
| CIS 6.8 | Guest with Owner/Admin role | L1 | identity.is_external + roles | collected | `slack-external-privileged` | critical |
| CIS 6.3 | Dormant admin (>90d inactive) | L1 | identity.last_active_at | collected | `slack-dormant-admin` | high |

## Section 3 — App governance

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| CIS 6.8 | App install requires admin approval | L1 | workspace app-approval policy | not-collectable | — | medium |
| CIS 6.8 | Overscoped installed apps | L1 | oauth_application + sensitive scopes | collected | `slack-app-overscoped` | high |
| CIS 6.8 | Unused installed apps | L2 | `admin.apps.activities.list` → `last_active_at`, stitched onto the approved-app record (Enterprise Grid) | collected | `slack-app-unused` | medium |
| — | Pending app requests unreviewed | L1 | pending_app_requests setting | collected | `slack-pending-app-requests` | medium |

## Section 4 — Data sharing & Connect

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| NIST PR.AC-3 | Slack Connect org connected | L1 | slack_connect_org_connected | collected | `slack-connect-org-connected` | medium |
| NIST PR.AC-3 | Externally shared channel | L1 | external_shared_channel | collected | `slack-external-channel-unrestricted` | high |
| NIST DE.CM-1 | Anomaly allowlist empty (Grid) | L2 | anomaly_allowlist_configured | collected | `slack-anomaly-allowlist-empty` | low |

## Section 4b — Information barriers (Enterprise Grid)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| NIST PR.AC-4 | Information barriers not configured | L2 | `admin.barriers.list` | collected | `slack-information-barrier-missing` | medium |

## Section 4c — Workflows (Enterprise Grid)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| NIST PR.DS-5 | Workflow shares data externally | L2 | `admin.workflows.search` → `is_external_steps_enabled` | collected | `slack-workflow-external-sharing` | high |

## Section 5 — Retention & DLP (Enterprise Grid)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| NIST PR.IP-6 | Private/shared channel without retention | L2 | `admin.conversations.getCustomRetention` | collected | `slack-channel-retention-missing` | medium |
| — | DLP rules not configured | L2 | DLP config | not-collectable | — | medium |

## Section 6 — Activity monitoring

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Privilege grant in Audit Logs | mon | event privilege.grant | collected | `slack-activity-privilege-grant` | high |
| — | App scope expansion | mon | event app.scope_expand | collected | `slack-activity-app-scopes-expanded` | high |
| — | External sharing activity | mon | event external.share | collected | `slack-activity-external-sharing` | high |
| — | Application installed into the workspace | mon | event oauth.app.install | collected | `slack-activity-app-installed` | high |
| — | Guest account created | mon | event identity.guest | collected | `slack-activity-guest-created` | medium |
| NIST DE.CM-3 | Workspace config change (pref_* events) | mon | event config.change | collected | `slack-activity-config-change` | medium |
| NIST DE.CM-3 | SSO configuration changed | mon | event sso.change | collected | `slack-activity-sso-change` | high |
| NIST DE.CM-3 | Security policy changed | mon | event policy.change | collected | `slack-activity-policy-change` | high |

## Section 7 — Channel membership (Kestrel controls)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Guest in a private or externally shared channel | L2 | channel membership grants (read up to `channel_membership_limit`) | collected | `slack-guest-in-private-channel` | medium |

## Framework mapping notes

- No CIS Slack Benchmark or CISA SCuBA baseline exists — `vendor_baselines` must remain empty or cite Slack docs only.
- Internal `custom` controls (`SLACK-xx`) are pack-local catalog entries, not CISA controls.
- Many L2 checks require Enterprise Grid; coverage view should report "not available on plan" when Admin APIs are skipped.

## A note on `not-collectable` here

Workspace 2FA enforcement and app-approval policy are marked `not-collectable`
because no Slack API returns them. They were previously marked `collected`
against policies that read fields `team.info` and `admin.teams.settings.info`
do not include — the values existed only in bundled fixtures, so on a live
tenant the checks either passed silently or, in the case of SSO, opened a
high-severity finding from a null. The exposure those checks aimed at is still
covered per account: `slack-privileged-without-mfa` and
`slack-external-without-mfa` read `has_2fa`, which Slack does return on
`users.list`.
