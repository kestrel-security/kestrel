# Slack connector setup

Walkthrough for connecting a Slack workspace or **Enterprise Grid** org.
Mirrored in the Integrations UI from `connectors/slack/manifest.yaml`.

## Which token to paste in Kestrel

Kestrel stores **one** secret (field name `bot_token`). Slack mints **two**
tokens after install — only one works for full Enterprise posture.

| Slack shows after install | Prefix | Paste in Kestrel? |
|---------------------------|--------|-------------------|
| **User OAuth Token** | `xoxp-…` / `xoxe-…` | **Yes — Enterprise Grid (recommended)** |
| **Bot User OAuth Token** | `xoxb-…` | **Workspace-only** fallback (no Admin Apps / Audit Logs) |

**Do not paste the Bot User OAuth Token when `enterprise_id` is set.** Admin
APIs and Audit Logs require the **user** token. Bot Token Scopes on the Slack
app do **not** apply to the User OAuth Token — if you only added
`users:read` under Bot Token Scopes, Test connection will fail on
`users.list` even when Admin scopes work.

## Scope placement (User vs Bot)

Slack attaches scopes to the token type you authorize. Kestrel calls the API
with whichever single token you pasted.

### Enterprise Grid (paste User OAuth Token)

Add **all** of these to **User Token Scopes** only:

| Scope | Purpose |
|-------|---------|
| `users:read` | Members + Owner/Admin flags |
| `users:read.email` | Email on identities |
| `usergroups:read` | User groups + membership |
| `channels:read`, `groups:read` | Channel inventory (public and private) and membership of private / shared channels |
| `team:read` | Workspace / team metadata |
| `admin.apps:read` | Approved / restricted / requested apps |
| `admin.roles:read` | Org system role assignments |
| `admin.teams:read` | Workspace list + settings |
| `admin.users:read` | Org-wide member inventory (`admin.users.list`) |
| `admin.conversations:read` | Externally shared channels (`admin.conversations.search`), per-channel retention |
| `auditlogs:read` | Enterprise Audit Logs (Org Owner install) |
| `admin.invites:read` | Pending invite requests (`admin.invites.invited.list`) |
| `admin.barriers:read` | Information barriers (`admin.barriers.list`) |
| `admin.usergroups:read` | IdP groups linked to channels (`admin.usergroups.listChannels`) |
| `admin.workflows:read` | Workflow inventory (`admin.workflows.search`) |
| `admin.analytics:read` | Member analytics for dormancy signals (`admin.analytics.getFile`) |
| `admin.auth.policy:read` | SSO / email-password policy assignments, i.e. who may bypass SSO (`admin.auth.policy.getEntities`) |

**Do not look for `conversations.connect:manage` under User Token Scopes.**
That scope is **bot-only** (see below). Ext-shared channel inventory uses
`admin.conversations:read` on the user token.

#### Bot Token Scopes (required for install — not what Kestrel pastes)

Slack’s OAuth install URL always sends bot scopes as `scope=` and user scopes
as `user_scope=`. If **Bot Token Scopes** is empty, `scope=` is empty and
Slack returns **`no_bot_scopes_requested`** — even when you only care about
the User OAuth Token.

Add **at least one** Bot Token Scope so install can finish:

| Scope | Purpose |
|-------|---------|
| `team:read` | **Required install stub** — satisfies Slack OAuth; Kestrel still pastes the User token |

Optional (still bot-only; unused while Kestrel pastes the user token):

| Scope | Purpose |
|-------|---------|
| `conversations.connect:manage` | `team.externalTeams.list` — Connect **org** catalog (needs bot token) |

After install, Slack shows both tokens. **Paste User OAuth Token (`xoxp` /
`xoxe`) into Kestrel** — not Bot User OAuth Token. The bot `team:read` stub
is only so OAuth succeeds.

After changing scopes, **reinstall** the app on the Enterprise org (Sharable
URL → org dropdown) and paste the new **User OAuth Token**.

### Workspace-only (paste Bot User OAuth Token)

For Pro/Business+ without Grid depth. Leave `enterprise_id` empty: the create
form marks it optional and only `team_id` is required. Grid-only families
(Admin Apps, org roles, Audit Logs, and the rest) are skipped and listed on the
run's coverage panel rather than failing the sync.

Add to **Bot Token Scopes** only:

| Scope | Purpose |
|-------|---------|
| `users:read` | Members + Owner/Admin flags |
| `users:read.email` | Email on identities |
| `usergroups:read` | User groups |
| `channels:read`, `groups:read` | Channel inventory and private-channel membership |
| `team:read` | Workspace metadata |
| `conversations.connect:manage` | Optional — Connect org inventory if available |

Paste **Bot User OAuth Token** (`xoxb-…`). Admin / Audit inventory is skipped
with classified health messages.

## Prerequisites

- **Enterprise Grid (recommended):** Org Owner; org-install app; User OAuth
 Token with all User Token Scopes above
- **Workspace-only:** Workspace admin; Bot User OAuth Token with bot scopes
 above

## Steps (Enterprise Grid)

1. Open [Slack API apps](https://api.slack.com/apps) → **Create New App** →
 From scratch.
2. **OAuth & Permissions → Bot Token Scopes** — add **`team:read`** (required
 install stub). Empty bot scopes → Slack error `no_bot_scopes_requested`.
3. **OAuth & Permissions → User Token Scopes** — add every scope in the
 Enterprise table above (member-read **and** admin **and** audit). Skip
 `conversations.connect:manage` here — it is not a user scope.
4. **Manage Distribution** → activate public distribution → copy **Sharable
 URL**.
5. Open the Sharable URL while logged in as **Org Owner**. In the install
 dropdown, select the **Enterprise organization** (`E…`), **not** a single
 workspace.
6. **Grant the app to your workspace.** Org install does **not** add the app
 to any workspace automatically. In Slack Org Admin → Integrations →
 Installed Apps → your app → Manage → **Add to more workspaces** → select
 Harbor / `T…`. Without this, sync fails with `team_access_not_granted`.
7. On **OAuth & Permissions**, copy **User OAuth Token** (`xoxp-…` / `xoxe-…`).
 **Not** Bot User OAuth Token (even though you added a bot scope stub).
8. In Kestrel → Integrations → Slack → **live**:
 - **bot_token** = User OAuth Token from step 7
 - **team_id** = workspace `T…` (same as External tenant ref)
 - **enterprise_id** = org `E…` (from `app.slack.com/manage/E…/T…/…` URL)
9. **Test connection** → expect core + Admin + Audit probes green.
10. **Sync now**.

**Kestrel does not host Slack’s OAuth install redirect.** Mint the token in
Slack, then paste it.

## Finding team_id and enterprise_id

- **enterprise_id (`E…`):** In the org admin URL:
 `https://app.slack.com/manage/E0BS7438GMD/T0BSNEBMQNN/…`
 Optional; set it only with an Enterprise Grid org-level user token. If such a
 token passes the Admin probes without `enterprise_id`, **Test connection**
 says so: Admin Apps and member inventory then cover only the `team_id`
 workspace.
- **team_id (`T…`):** Same URL (second segment), or workspace **About this
 workspace**, or [auth.test](https://api.slack.com/methods/auth.test) with
 your User OAuth Token.

## Troubleshooting

| Test connection / sync error | Likely cause | Fix |
|------------------------------|--------------|-----|
| Admin APIs ✅, `users.list` / `usergroups.list` ❌ | Bot token pasted, or member scopes only on **Bot Token Scopes** | Add member scopes to **User Token Scopes**, reinstall on org, paste **User OAuth Token** |
| `conversations.connect:manage` missing from User scopes | Correct — it is bot-only | Ignore for Enterprise user-token path; use `admin.conversations:read` for shared channels |
| `no_bot_scopes_requested` on install | Bot Token Scopes empty (`scope=` blank) | Add **`team:read`** under **Bot Token Scopes**, reinstall; still paste **User** OAuth Token into Kestrel |
| `team_access_not_granted` | Org-installed app not granted to workspace `team_id` | Org Admin → Integrations → Installed Apps → app → **Add to more workspaces** (include `T…`). Org install does **not** auto-add workspaces |
| `missing_scope` on `team.info` | User token missing `team:read` | Add to **User Token Scopes**, reinstall |
| Admin / Audit ❌, core ✅ | Workspace install or missing admin scopes | Org-install; add admin + `auditlogs:read` to **User Token Scopes** |
| `invalid_auth` / `token_revoked` | Stale token | Reinstall app; paste fresh User OAuth Token |
| Sync stuck **running** forever | Worker crashed mid-task | Restart the worker; sync again |

## Live sync behavior

- List endpoints walk Slack **cursor** pagination (`limit=200`). A remaining
 cursor after the page cap **raises** — inventory is never silently truncated.
- Org user tokens pass `team_id` on `users.list` and `usergroups.list`.
- Audit Logs use `https://api.slack.com/audit/v1` (same Bearer token).
- **Test connection** probes core inventory plus Enterprise families (Admin
 Apps, org roles, workspaces, Audit Logs).
- **A workspace-only token degrades visibly.** Everything past team, members,
 usergroups, and owner/admin roles needs Enterprise Grid with an org-installed
 User OAuth Token. With a bot token the Grid families (Admin Apps, org roles,
 workspaces, Connect orgs, ext-shared channels, anomaly allowlist, Audit Logs)
 skip, are recorded by name, and mark the run **PARTIAL_FAILURE**. Deletion
 detection and snapshot writing are suppressed for that run, so the families
 you cannot read are never reported as revoked access in Changes.
- A throttled request is not a gate: `ratelimited` retries and then fails the
 run rather than reporting an empty family.

## Honest limits

- No hosted Slack OAuth install UI — paste an already-minted token.
- Full posture requires **Enterprise Grid** + org-installed **User OAuth
 Token** with all User Token Scopes.
- Slack Connect **org** catalog (`team.externalTeams.list`) needs bot scope
 `conversations.connect:manage`; single-token Enterprise sync may skip it.
 Ext-shared channels use user scope `admin.conversations:read`.
- `last_used_at` is not returned live by `admin.apps.approved.list`, so
 `slack-app-unused` has no signal on a live tenant. Reading it needs
 `admin.apps.activities.list`.
- Audit Logs are curated (not a SIEM dump). Message content / write-back out
 of scope.
- **Workspace 2FA enforcement and app-approval policy are not collectable.**
 Neither `team.info` nor `admin.teams.settings.info` returns them, and no
 other Slack method exposes them. Per-account 2FA *is* collected
 (`users.list` → `has_2fa`) and drives `slack-privileged-without-mfa` and
 `slack-external-without-mfa`. Workspace-wide SSO *enforcement* is not a
 Slack setting either; what Kestrel collects is the SSO policy assignment
 list from `admin.auth.policy.getEntities` (`sso_policy`, Enterprise Grid +
 `admin.auth.policy:read`), which is what `slack-sso-not-enforced` reads to
 tell who may still sign in with email and password.
- Session duration is per account, not per workspace
 (`admin.users.session.getSettings`, Enterprise Grid + `admin.users:read`).
 Accounts with no explicit setting are absent from the response and get no row
 — that is "Slack applied no setting", not "the session is short".

## Findings after sync

Enable `packs/slack-posture`. To stage a sandbox that trips the policies, see
[Building a test tenant](#building-a-test-tenant).

## Building a test tenant

Use a Slack Developer Program / Enterprise Grid sandbox you are willing to make
ugly. Never commit tokens or signing secrets; keep only `team_id` (`T…`) and
`enterprise_id` (`E…`) in your own notes.

1. Create an app at [api.slack.com/apps](https://api.slack.com/apps). Add `team:read` under **Bot Token Scopes** (Slack refuses to install an app with no bot scopes). Under **User Token Scopes** add what Kestrel uses: `users:read`, `users:read.email`, `usergroups:read`, `team:read`, `admin.apps:read`, `admin.roles:read`, `admin.teams:read`, `admin.users:read`, `admin.conversations:read`, `auditlogs:read`.
2. Manage Distribution → activate → install as **Org Owner** on the **Enterprise organization** (choose the org in the dropdown, not a workspace).
3. Copy the **User OAuth Token** (`xoxp` / `xoxe`), not the Bot User OAuth Token.
4. In Kestrel: Integrations → Add integration → Slack → **live**; `bot_token` is the User OAuth Token, `team_id` a workspace id, `enterprise_id` the org id. **Test connection** should be green on every probe; if Admin probes pass but `users.list` fails, member scopes are missing from User Token Scopes.

Stage identities and settings:

| Person / setting | State | Exercises |
|------------------|-------|-----------|
| A Primary Owner or Org Admin with 2FA | | Explore hop |
| A Workspace Admin without 2FA | | `slack-privileged-without-mfa` |
| Optional dormant Admin | stale activity | `slack-dormant-admin` |
| A guest without 2FA | | `slack-external-without-mfa` |
| A member with a long session duration | 30 days | `slack-session-duration-excessive` |
| A third-party or internal app with `chat:write` or `channels:history` | approved | `slack-app-overscoped` |
| Optional Slack Connect org or ext-shared channel | connected | `slack-connect-org-connected`, `slack-external-channel-unrestricted` |

For Audit Logs activity policies, promote someone to Admin or expand an app's
scopes shortly before syncing.

Then: Sync now → Explore (search the Admin; confirm the role grant, OAuth app
nodes with `possesses_scope` hops, and the Slack Connect discovered org when
those inventories succeeded) → Findings (enable `slack-posture`) →
optionally promote a member to Admin, sync, and confirm `admin_granted` in
Changes.

Out of scope for the smoke: the Discovery API and message content,
write-back, a hosted OAuth redirect, SCIM as a second catalog, full
public-channel inventory. Tear down by revoking the user token or uninstalling
the org app and deleting the connector instance.

## Related

- `connectors/slack/README.md`
- [`connectors.md`](../connectors.md) (SDK, instance and secret handling, live smoke checklist)
- [Slack rate limits](https://api.slack.com/docs/rate-limits)
- [Audit Logs API](https://docs.slack.dev/admins/audit-logs-api)
- [`conversations.connect:manage` (bot only)](https://docs.slack.dev/reference/scopes/conversations.connect.manage)
