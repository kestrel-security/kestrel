# Kestrel connector: Okta

Collects Okta users, groups, classic and custom IAM admin roles (direct and
group-assigned), application assignments, OAuth apps, authentication and
session policies, perimeter settings, behaviors, log streams, authorization
servers, devices, and **System Log** activity into Kestrel's normalized model.

**Status:** live sync + fixture backup. Collection, normalization, and full
sync work with no credentials (fixtures). Live mode authenticates with either
an OAuth 2.0 service app (`client_id` + `private_key_pem`, recommended) or an
SSWS API token (`api_token`, legacy), and walks RFC 5988 `Link` pagination
(`limit=200`) until Okta stops sending `rel=next` — the client does not
silently cap at one page.

## Object types

The rows below are the `object_types` in `manifest.yaml` (36), with the entity
kind each one maps to. The extended families at the end need the OAuth scopes
in `required_scopes` (or Super Admin on an SSWS token) and are skipped and
recorded, never failed, when the credential cannot read them.

| Object type | Maps to | Notes |
|---|---|---|
| `org` | setting | Org MFA enrollment + subdomain. |
| `user` | identity | Status → disabled; factors → `mfa_enabled`; contractors → external. |
| `group` | group | Okta groups. |
| `group_member` | group_membership | `{group}:{user}`. |
| `admin_role` | role | Classic admin role catalog (SUPER_ADMIN, APP_ADMIN, …). |
| `role_assignment` | grant | Direct `/users/{id}/roles` plus group-inherited `/groups/{id}/roles`. |
| `app` | oauth_application | All apps (OIDC + SAML). |
| `app_scope` | oauth_scope | From OIDC `oauthClient.scopes`. |
| `app_group` | oauth_grant | Groups assigned to an app; also a `can_access` group→app graph edge so Explore routes through the group. |
| `app_user` | oauth_grant | Direct (`scope=USER`) app assignments. Group-scoped users are skipped so Explore goes through the group. |
| `system_log` | event (incremental) | Curated System Log (privilege, MFA, threat, admin console, token create), cursored from the previous run. |
| `password_policy` | setting | Password min length / complexity from `GET /api/v1/policies?type=PASSWORD`. |
| `mfa_enroll_policy` | setting | Whether an active MFA_ENROLL policy requires a factor (`mfa_enroll_policy_required`). |
| `threat_insight` | setting | Threat Insight enabled flag (`GET /api/v1/threats/configuration`). |
| `api_token` | identity | Org API tokens as `service_account` identities with last activity. |
| `app_sign_on_setting` | setting | Per-app `signOnMode` for SSO vs bookmark/SWA posture policies. |
| `access_policy`, `sign_on_policy`, `profile_enrollment_policy`, `idp_discovery_policy` | setting | Policies with their rules attached, plus a roll-up of the active rules (`any_rule_without_mfa`, `any_rule_unlimited_session`, `longest_session_minutes`). Unreadable rules are recorded as a skip, never as "no rules". |
| `authenticator` | setting | Authenticator catalog and status; phishing resistance is a property of the authenticator, not of having MFA. |
| `device_assurance_policy` | setting | Device assurance policies. |
| `network_zone` | setting | IP and dynamic zones; a policy zone containing `0.0.0.0/0` matches everything. |
| `trusted_origin` | setting | Origins allowed to make cross-origin calls and receive redirects. |
| `event_hook`, `inline_hook` | setting | Hook definitions with the callout URL reduced to host and scheme and auth headers dropped at collection. |
| `identity_provider` | setting | Inbound federation, including whether the IdP provisions users just in time. |
| `group_rule` | setting | Dynamic group membership rules. |
| `iam_role` | role | Custom IAM roles (`/api/v1/iam/roles`) with their permission lists. |
| `resource_set` | setting | OIE resource sets (`/api/v1/iam/resource-sets`) that scope custom roles. |
| `behavior` | setting | Behavior detection rules (`/api/v1/behaviors`) and whether each is active. |
| `log_stream` | setting | System Log streaming destinations (`/api/v1/logStreams`). |
| `auth_server` | setting | Custom authorization servers with their access policies and scopes. |
| `entity_risk_policy`, `post_auth_session_policy` | setting | Entity-risk and post-authentication session policies, with their rules. |
| `device` | resource | Registered devices (`/api/v1/devices`) and the users bound to them. |

After a successful sync, Explore should show privileged identities (for
example Ada → Super Administrator, `access_path=direct`) and group-inherited
classic admin roles (`access_path=inherited_group`). Searching a group (for
example **engineering**) opens direction **Both**: members on the left, apps
the group is assigned to on the right.

## Fixture mode

```bash
uv run kestrel connector validate connectors/okta
uv run pytest tests/unit/connectors -k okta -q
```

Config: `{"org_url": "https://acme.okta.com"}`. Secrets unused in fixtures mode.

Ada Lovelace is **Super Administrator** (direct) with MFA. Grace Hopper is
**Application Administrator** without MFA (flagged by the okta-posture pack)
and is the `kestrel demo change` promotion target (Grace → Super Administrator).
The security group also carries **Group Administrator**, inherited by Ada and
Grace.

## Live mode

Full setup walkthrough: [`docs/connectors/okta-setup.md`](../../docs/connectors/okta-setup.md)
(also shown in Integrations → Add integration). Throwaway-org staging:
[`docs/connectors/okta-setup.md`](../../docs/connectors/okta-setup.md#building-a-test-tenant).

- Auth methods: `oauth` (OAuth 2.0 service app, secrets `client_id` +
  `private_key_pem`; recommended, and the only method whose scopes are exact —
  they are the manifest's `required_scopes`) or `pat` (secret `api_token`, an
  SSWS token that inherits its creating admin's permissions)
- Config: `org_url` must be HTTPS and pass the SSRF guard. Use
  `https://<org>.okta.com`, not the Admin Console `*-admin.okta.com` host
  (that host is rewritten automatically). The host must be on an Okta-owned
  domain (`*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com`,
  `*.okta-gov.com`, `*.okta.mil`) so the token cannot be sent elsewhere; a
  custom Okta domain works only if the deployment lists it in
  `KESTREL_CONNECTOR_URL_ALLOWLIST`. Changing `org_url` clears the stored
  secrets. Org settings come from `GET /api/v1/org`.
- Live lists paginate via `Link` headers (`limit=200`); Test connection uses
  `limit=1` probes (org, users, groups, apps, one user's classic roles, System
  Log) and classifies auth vs permission vs rate_limit vs network failures
- Nested 403/404 (factors, roles, group members, app users, **app groups**,
  **System Log**) skip that join and continue; top-level users/groups/apps
  failures fail the sync
- **System Log** (`GET /api/v1/logs`) is in scope: last ~7 days by default
  (Okta's own default when `since` is omitted), Link-paginated, mapped to
  activity `event` rows so privilege / MFA / threat events reach policies
  without waiting on the next directory diff. Unmapped types (for example routine
  `user.session.start`) are not stored.
- Rate limits: Okta Management API org limits apply; the live transport retries
  **429** a few times (`Retry-After` when present). See
  [Okta rate limits](https://developer.okta.com/docs/reference/rl-global-mgmt/)

Enable `packs/okta-posture` for posture findings (`okta-admin-without-mfa`,
`okta-mfa-enroll-not-required`, `okta-disabled-privileged-admin`, `okta-dormant-admin`,
`okta-password-policy-weak`, `okta-password-allows-username`,
`okta-app-bookmark-or-swa`, `okta-api-token-unused`,
`okta-device-assurance-without-disk-encryption`,
`okta-threat-insight-disabled`) and System Log event policies
(`okta-activity-privilege-grant`, `okta-activity-privilege-revoked`,
`okta-activity-mfa-disabled`, `okta-activity-threat-detected`,
`okta-activity-api-token-created`). The full control-by-control mapping,
including what is *not* covered, is
[`docs/posture-baselines/okta.md`](../../docs/posture-baselines/okta.md).

## Honest limits (not in scope)

- **Full System Log streaming / SIEM export** is not implemented — Kestrel
  polls `/api/v1/logs` on each sync and keeps a **curated** eventType map
  (privilege grant/revoke, MFA factor deactivate, threat detected, admin
  console access, user suspend/deactivate, API token create). Routine logins
  are dropped.
- **Okta Workflows** are not collected or executed.
- **Write-back / remediation** (create users, change roles, revoke apps) is
  not implemented. Tokens should be read-oriented; Kestrel does not call
  mutating Management API endpoints.
- **Identity Governance** certifications and access requests are not collected.
- **Custom IAM roles, resource sets, behaviors, log streams, authorization
  servers, and devices** are collected only when the credential can read them
  (the OAuth scopes above, or Super Admin on an SSWS token); otherwise they are
  recorded as skipped families.
- **Device trust** policies and full **password policy rule trees** are summarized, not rule-complete.
- **Rate-limit** settings beyond Threat Insight are not collected.
- **Group → app assignments** are graph edges (`can_access`) only — they do
  not create Grant / OAuthGrant rows, so Changes may not classify them as
  first-class grant events.
- Very large orgs: sync duration scales with page count (users × factors/roles
  plus groups × members/roles plus apps × assignments). List responses are
  cached on the client for one sync so users/groups/apps are not re-walked.
  Prefer off-peak schedules. Core `LiveHTTPTransport` raises if a single list
  exceeds 10,000 pages (not a silent truncate).
- Cross-host pagination `Link` targets are refused.

## Collection gaps (honest)

See [`docs/posture-baselines/okta.md`](../../docs/posture-baselines/okta.md)
for the control → capability matrix. Capability keys on `manifest.yaml`
(`provides_capabilities`) drive pack coverage reporting.

IdP is the identity spine. Prefer Okta user linkage for cross-app identity
correlation when this connector is connected.
