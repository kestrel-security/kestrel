# Google Workspace connector setup

Walkthrough for domain-wide delegation (live auth, live
pagination). Mirrored in the Integrations UI from
`connectors/google_workspace/manifest.yaml`.

## Prerequisites

- Google Cloud project with the following APIs enabled (all free tiers, no billing required for these):
  - **Admin SDK API** (covers Directory + Reports)
  - **Google Drive API**
  - **Cloud Identity API** (for Policy API settings)
  - **Google Workspace Alert Center API** (for Alert Center)
- Ability to enable domain-wide delegation in Workspace Admin
- A **Super Admin** mailbox to impersonate, or a custom admin whose privileges
  you have verified (see [Delegated admin](#delegated-admin-super-admin-vs-custom-roles))

## Enabling the required GCP APIs

In your Google Cloud project:
```
gcloud services enable \
  admin.googleapis.com \
  drive.googleapis.com \
  cloudidentity.googleapis.com \
  alertcenter.googleapis.com
```

Or via the [APIs & Services](https://console.cloud.google.com/apis/library) console.

## Steps

1. [Service accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) → create SA → JSON key.
2. Enable **domain-wide delegation**; note the numeric Client ID.
3. [Domain-wide delegation](https://admin.google.com/ac/owl/domainwidedelegation) → Add Client ID + these scopes (comma-separated, exact strings):

   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/cloud-identity.devices.readonly,https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly,https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/apps.alerts
   ```

   This is exactly the `required_scopes` list in
   `connectors/google_workspace/manifest.yaml`. Every scope is a read-only
   variant except three that Google offers no read-only form of:
   `apps.groups.settings`, `admin.directory.user.security` (per-user OAuth
   tokens), and `apps.alerts`. Kestrel only reads through them.

   **Minimal scopes** (identity, Drive, and Admin Reports only — fewer privileges if you do not need Alert Center, the Policy API, or devices):
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```

4. Choose a delegated admin email (prefer Super Admin).
5. In Kestrel Integrations:
   - Config: `domain` = primary Workspace domain (e.g. `acme.example.com`)
   - Secrets: paste full `service_account_json` and `delegated_admin_email`
   - Sync mode: **live**
6. **Test connection**, then **Sync now**.

Kestrel mints an OAuth2 access token by signing a JWT assertion with the service
account key and exchanging it at Google’s token endpoint (impersonating the
delegated admin). Tokens are never stored; each sync/test mints a fresh one.

## Delegated admin: Super Admin vs custom roles

Domain-wide delegation scopes on the **service account** are necessary but not
sufficient. Google still evaluates the **impersonated user's** Admin console
privileges.

| Impersonate | Directory users/groups/roles | Shared drives (domain-wide) | Admin Reports (audit activity) |
|---|---|---|---|
| **Super Admin** | yes | yes | yes |
| Built-in Help Desk / Groups Admin | usually no (not full Directory + Drive domain-admin) | no | no |
| Custom role | only if it includes Users/Groups/Role management **read** | only if it includes Drive **as domain admin** | only if it includes Reports |

Kestrel reads `rolePrivileges` and marks a role privileged when it carries a
privilege that changes who can sign in, what they can reach, or the security
configuration — so a custom role with Super-Admin-like APIs *is* flagged, and one
with only reporting access is not. Privilege is never inferred from `roleName`.
See `connectors/google_workspace/README.md`.

Prefer Super Admin for the first live smoke. A least-privilege custom role is
fine later if Test connection shows all required probes green
(`directory.*` + `drive.drives`). `reports.login` may stay red; sync will still
collect identity and Drive, and skip the Admin Reports activity feeds.

## Live sync behavior

- Users and groups are listed with ``customer=my_customer`` (every domain in
  the Workspace), not filtered to the configured primary domain. ``domain`` in
  config is used for the domain settings object.
- Shared drives and permissions use ``useDomainAdminAccess=true`` so drives the
  delegated admin is not a member of are not dropped.
- Directory, Drive, and Admin Reports list calls walk Google
  ``nextPageToken`` until exhausted. Hitting the page cap with a remaining
  token **fails the list** (no silent truncation).
- **Test connection** probes domain + single-page ``maxResults=1`` /
  ``pageSize=1`` list calls (does not walk the full directory). Reports is
  optional: a Reports 403 still leaves Test connection healthy for the
  identity/drive path.
- Failures distinguish **authentication**, **permission**, **rate_limit**, and
  **network** where the transport exposes status codes.
- HTTP **429** responses retry using shared live transport ``Retry-After``
  handling.

## Optional families

Beyond the core families (users, groups, drives, roles, tokens, login activity),
the connector collects:

| Object type | API | Kestrel kind |
|---|---|---|
| `customer` | Directory customers | `setting` |
| `policy` | Cloud Identity Policy API (OU-scoped) | `setting` |
| `mobile_device` | Directory mobile devices | `resource:device` |
| `chromeos_device` | Directory ChromeOS devices | `resource:device` |
| `alert` | Alert Center | `event` + `alert_count_setting` |
| `inbound_sso_profile` | Cloud Identity inbound SAML | `setting` |
| `inbound_sso_assignment` | Cloud Identity SSO assignments | `setting` |
| `admin_activity` | Admin Reports `admin` | `event` |
| `drive_activity` | Admin Reports `drive` | `event` |
| `saml_activity` | Admin Reports `saml` | `event` |
| `user_accounts_activity` | Admin Reports `user_accounts` | `event` |
| `groups_activity` | Admin Reports `groups` | `event` |
| `mobile_activity` | Admin Reports `mobile` | `event` |
| `dwd_client` | Synthesized from admin audit | `oauth_application` |

All of these families are optional: if the scope or API is missing, the
skipped type is recorded and collection continues.

## Honest limits

- **Fixtures** remain the CI/demo path (`sync_mode=fixtures`) — no credentials needed.
- Prefer a dedicated Super Admin (or verified custom role) for
  `delegated_admin_email`, not a day-to-day user mailbox.
- Chrome extensions are not collected.
- Nested groups produce a one-hop group-to-group edge, but Google's
  `includeDerivedMembership` expansion is not walked, so membership inherited
  through a chain of nested groups is not enumerated.
- Very large tenants: sync duration scales with page count; prefer off-peak
  schedules. A remaining `nextPageToken` after the cap is an error, not a
  partial success.
- Live smoke (Test → Sync → Explore → ≥1 finding) has to be run against a real tenant; it has not been signed off yet.
- DWD client objects are synthesized from admin audit; they reflect the last
  known AUTHORIZE/REVOKE event, not a live API snapshot.

## Related

- `connectors/google_workspace/README.md`
- Live smoke: [`connectors.md`](../connectors.md#live-smoke-checklist)
