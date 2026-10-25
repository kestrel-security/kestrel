# Okta connector setup

**Two auth methods:** OAuth 2.0 service app (recommended for new integrations,
supports every extended family below) or API token / SSWS (legacy, still supported).
Both are mirrored in the Integrations UI from `connectors/okta/manifest.yaml`.

Prefer **live** sync for real posture data. Fixtures remain for CI and offline
demos (`kestrel demo up`). Staging a throwaway org:
the [Building a test tenant](#building-a-test-tenant) section below.

## Option A — OAuth 2.0 service app (recommended)

The service-app method grants exact OAuth scopes rather than inheriting a
human admin's permissions. It is the recommended path for new integrations and
required for the extended families (behaviors, log streams, custom IAM roles,
auth servers, devices).

### Prerequisites

- Okta Admin Console Super Admin access (to create the service app and grant scopes)
- A Kestrel deployment with `kestrel-connector-okta` installed (connector manifest 0.4 or later)

### Steps

1. Sign in to the [Okta Admin Console](https://login.okta.com/).
2. **Applications → Create App Integration → API Services.** Name it "Kestrel".
3. On the app's **General** tab → **Client Credentials → Edit → Public key /
   Private key → Add key**. Generate an RSA-2048 key pair, **save the private key
   PEM** (shown once), and upload the public key to Okta. Note the **Client ID**.
4. On the app's **Okta API Scopes** tab, grant every scope listed below.
   Kestrel degrades gracefully (records skips) on missing scopes.
5. In Kestrel: Integrations → Add integration → Okta → Auth method: **OAuth 2.0
   service app**. Config: `org_url`. Secrets: `client_id`, `private_key_pem`.
6. **Test connection** then **Sync now**.

### Required OAuth scopes

```
okta.users.read            okta.groups.read            okta.apps.read
okta.roles.read            okta.policies.read          okta.authenticators.read
okta.logs.read             okta.authorizationServers.read  okta.orgs.read
okta.behaviors.read        okta.devices.read           okta.logStreams.read
okta.brands.read           okta.domains.read           okta.realms.read
okta.apiTokens.read
```

---

## Option B — API token (SSWS, legacy)

### Prerequisites

- Okta Admin Console access that can create API tokens and read users, groups,
  classic admin roles, apps, and **System Log**
- A Kestrel deployment with `kestrel-connector-okta` installed

### Steps

1. Sign in to the [Okta Admin Console](https://login.okta.com/).
2. Security → API → Tokens → Create Token ("Kestrel"). Copy once.
3. Set `org_url` to `https://<your-org>.okta.com` (HTTPS only; must pass SSRF checks).
   Kestrel only sends credentials to Okta-owned domains (`*.okta.com`,
   `*.oktapreview.com`, `*.okta-emea.com`, `*.okta-gov.com`, `*.okta.mil`). To use
   a custom Okta domain instead, the deployment operator must add its hostname to
   `KESTREL_CONNECTOR_URL_ALLOWLIST`; using the `okta.com` org URL is simpler.
   Changing `org_url` later clears the stored secrets, so re-enter them with the change.
   Do **not** paste the Admin Console host (`https://<your-org>-admin.okta.com`) — that
   is the UI, not the Management API. Kestrel rewrites `*-admin.okta.com` automatically
   if you do.
4. Paste `api_token` on the Secrets step; choose **live** (or fixtures for offline).
5. **Test connection** then **Sync now** on the instance page.

Okta API tokens inherit the creating admin's permissions (not OAuth scopes). Prefer a
dedicated service account. **Org Admin or Super Admin** yields a complete inventory
(users, groups, classic roles, apps). The extended families (behaviors, log streams,
custom IAM roles, auth servers, devices) require Super Admin or specific OAuth scopes;
they degrade visibly on SSWS tokens without sufficient access.

---

## Live sync behavior

- List endpoints (users, groups, apps, factors, roles, group members, group
  roles, app users, **System Log**) walk Okta's RFC 5988 `Link` pagination with
  `limit=200` per page until there is no `rel=next`. The client concatenates
  every page; it does not keep only the first 200 rows.
- System Log uses Okta's default window (about the last **7 days**) when the
  runner does not pass `since`. Events map to activity rows for ~100 event types
  including privilege grants, MFA changes, threat detections, admin-console access,
  policy changes, zone changes, IAM role changes, device events, impersonation, and
  more. Routine `user.session.start` logins are not stored.
- Pagination `Link` targets must stay on the same `org_url` host (cross-host next URLs are refused).
- HTTP **429** responses retry a few times using `Retry-After` when present (shared live transport).
- **Test connection** probes `GET /api/v1/org`, `users|groups|apps?limit=1`,
  classic roles for the first returned user, and `logs?limit=1`. Missing System
  Log permission (403) does **not** fail Test connection — directory sync still
  works and event detections are skipped until the token can read logs.
- Health failures distinguish **authentication** (401), **permission** (403),
  **rate_limit** (429), and **network** errors in the message.
- **Partial access degrades the run rather than hiding.** A 403/404 on an optional
  family skips that family, records it, and marks the run **PARTIAL_FAILURE**.
  Deletion detection and snapshot writing are suppressed for that run, so the
  missing rows are never reported as revoked access in Changes.
- A **429** is not a permission gate. Once retries are exhausted the sync
  fails rather than reporting an empty family, because a throttled run and an
  empty tenant are indistinguishable downstream.

## Extended families

| Family | Endpoint | Requires |
|--------|----------|----------|
| Custom IAM roles | `/api/v1/iam/roles` + `/permissions` | `okta.roles.read` |
| Resource sets | `/api/v1/iam/resource-sets` | `okta.roles.read` |
| Behavior detection | `/api/v1/behaviors` | `okta.behaviors.read` |
| Log streams | `/api/v1/logStreams` | `okta.logStreams.read` |
| Authorization servers | `/api/v1/authorizationServers` + `/policies` + `/scopes` | `okta.authorizationServers.read` |
| Devices | `/api/v1/devices` + `/users` | `okta.devices.read` |
| Entity risk policies | `/api/v1/policies?type=ENTITY_RISK` | `okta.policies.read` |
| Post-auth session policies | `/api/v1/policies?type=POST_AUTH_SESSION` | `okta.policies.read` |

All extended families are optional — they degrade visibly (recorded in
`skipped_object_types`) on SSWS tokens without sufficient access or on orgs
where the feature is not enabled. The run continues and remaining families are
collected.

## Authentication and session policy

Okta policies are **containers**; the controls live on their rules. A sign-on
policy says nothing on its own — whether a session lasts eight hours or forever,
whether a second factor is required, and which network zones apply are all rule
properties.

Collected, each with its rules:

| Family | Endpoint |
|--------|----------|
| Authentication policies | `/api/v1/policies?type=ACCESS_POLICY` |
| Global session policies | `/api/v1/policies?type=OKTA_SIGN_ON` |
| Profile enrollment policies | `/api/v1/policies?type=PROFILE_ENROLLMENT` |
| Identity provider routing | `/api/v1/policies?type=IDP_DISCOVERY` |
| Rules for each of the above | `/api/v1/policies/{id}/rules` |
| Authenticators | `/api/v1/authenticators` |
| Device assurance policies | `/api/v1/device-assurances` |

Each policy setting carries its active rules plus a **roll-up**, because the
security question is never "what does this policy say" — it is "does *any*
active rule let a session run forever, or skip a second factor". An attacker
gets whichever rule is loosest, so `any_rule_without_mfa`,
`any_rule_unlimited_session`, and `longest_session_minutes` summarize the
weakest one. Inactive rules are excluded; an inactive rule enforces nothing and
counting it would make a tightened policy read as permissive.

**Two things worth knowing about the data:**

- Okta encodes an unlimited session lifetime as **0 minutes**. A rule that looks
  like it expires immediately may never expire at all, so `unlimited_lifetime`
  is reported explicitly rather than passing the raw number through.
- Phishing resistance is a property of the *authenticator*, not of having MFA.
  Okta Verify push and OTP can both be relayed by an attacker-in-the-middle
  proxy; WebAuthn and smart cards cannot. `okta-no-phishing-resistant-authenticator`
  fires when the only enabled factors are phishable.

**If policy rules are unreadable**, the skip is recorded rather than the policy
being reported as having no rules — a policy with no rules summarizes as one
that requires nothing and expires nothing, so a permission gap would read as a
wide-open sign-on policy.

## Perimeter and automation

Six more families, covering who can reach the org and what runs when they do:

| Family | Endpoint | Why it matters |
|--------|----------|----------------|
| Network zones | `/api/v1/zones` | A policy zone containing `0.0.0.0/0` matches the whole internet while looking like a network control |
| Trusted origins | `/api/v1/trustedOrigins` | A redirect-scoped origin can receive a token, so this is an authentication boundary, not a CORS convenience |
| Event hooks | `/api/v1/eventHooks` | Identity events delivered to an external endpoint |
| Inline hooks | `/api/v1/inlineHooks` | **Runs during authentication and can change its outcome** |
| Identity providers | `/api/v1/idps` | Inbound federation; JIT provisioning means an assertion creates an account |
| Group rules | `/api/v1/groups/rules` | Dynamic membership turns a profile attribute into a group grant |

**Hook URLs are never stored.** Okta hook callout URLs carry authentication in
the path or in headers, and an inline hook's endpoint is itself a trust
boundary. Only the host and scheme are kept, and `authScheme` and `headers` are
dropped — at collection, because `raw_source` is persisted verbatim.

## After connect

- Secrets are envelope-encrypted; API responses never return plaintext.
- Enable a schedule on the instance for continuous syncs.
- Enable `packs/okta-posture`. After sync, **Explore**
  a known Super Admin, then a group that is assigned an app (direction
  **Both**: members left, apps right). **Findings** should include posture
  hits (`okta-admin-without-mfa`, `okta-mfa-enroll-not-required`, plus
  disabled-admin / dormant-admin / weak-password / bookmark-app / unused-token
  when those conditions exist) and, when System Log has a matching event,
  `okta-activity-*` detections.
- Custom Python policies: **Policies → New** can generate Okta-grounded drafts
  from intent chips (works offline for known templates) or Settings → AI for
  novel intents. See [`policies.md`](../policies.md#ai-assisted-drafts).
- Optional Changes beat: promote a user to Super Admin in Okta, sync again,
  confirm an `admin_granted` (or similar) row. If you have no live tenant for
  that beat, `kestrel demo change` still promotes fixture Grace Hopper to
  Super Administrator.

## Honest limits (not in scope)

- **Okta Workflows** are not collected or executed.
- **Write-back** (create/deactivate users, assign roles, revoke apps) is not
  implemented. Do not grant the token more write than you must; Kestrel does
  not call mutating endpoints today.
- System Log is **in scope** as a curated poll of `/api/v1/logs` (not a
  streaming SIEM export). Unmapped event types are dropped.
- Very large orgs: duration scales with page count; prefer off-peak schedules.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Test connection: authentication | Expired/wrong SSWS token; rotate under Security → API → Tokens. For OAuth: check client_id and that the private_key_pem matches the key registered on the app. |
| Test connection: permission | Token admin cannot read users/groups/apps/roles; use Org/Super Admin. For OAuth: grant required scopes on the app's Okta API Scopes tab. |
| Test connection: rate_limit | Org Management API limit; wait and retry |
| Test connection / sync: 404 on `/api/v1/orgs/default` | Old connector bug (fixed: live path is `GET /api/v1/org`). Rebuild API/worker images. |
| Sync now: `datetime is not JSON serializable` | Identity `last_active_at` diffs were written as raw datetimes into change events (fixed). Restart the worker and Sync now. |
| Test connection: network | Bad `org_url`, DNS, or worker egress |
| Explore missing Super Admin | Token cannot read `/users/{id}/roles`; or the user is DEPROVISIONED |
| Explore group has members but no apps | App is assigned to users only, not the group; or token cannot read `/apps/{id}/groups` |
| Findings empty | Enable okta-posture; stage an admin without MFA; confirm System Log permission |
| SSRF / invalid URL | `org_url` must be public HTTPS (no private IPs) on an Okta-owned domain, or an allowlisted custom domain. Admin Console `*-admin.okta.com` is rewritten to the org API host. |
| Extended families all skipped | SSWS token lacks Super Admin; use OAuth service-app with all required scopes |

## Building a test tenant

A throwaway Okta org that exercises the pack end to end (Test → Sync →
Explore → Findings). Never commit tokens, org URLs with credentials, or
screenshots that show secrets; keep only the `org_url` host in your own notes.

1. Create an [Okta Integrator Free Plan](https://developer.okta.com/signup/) org or a dedicated non-production org. Never use a production tenant.
2. As Super Admin: Security → API → Tokens → Create Token (for example `kestrel-smoke`). Copy it once.
3. In Kestrel: Integrations → Add integration → Okta → **live**. `org_url` is `https://<your-org>.okta.com` (not the `-admin` host); `api_token` is the SSWS token.
4. **Test connection.** Expect a classified failure if the token or URL is wrong.

Stage identities so policies have something to find:

| Person | Okta state | Exercises |
|--------|------------|-----------|
| A known Super Admin | Super Administrator with MFA enrolled | Explore hop |
| An App / Org / Help Desk / Group admin without MFA | Classic admin role, no active factors | `okta-admin-without-mfa` |
| Optional group-assigned admin | Classic admin role assigned to a group with a member | Explore `inherited_group` |

Leave the org MFA enrollment policy off or not required to exercise
`okta-mfa-enroll-not-required`. Assign at least one OIDC app, preferably to a
group, so Explore shows an OAuth hop with members on one side and apps on the
other. For System Log detections, stage a privilege grant or factor deactivate
shortly before syncing; the connector keeps a curated event-type map and does
not store routine logins.

Then: Sync now → Explore (search the Super Admin; confirm the role node and
`assigned_role`, or `inherited_group` for the group-assigned admin) → Findings
(enable `okta-posture`) → optionally promote someone to Super Admin, sync
again, and confirm `admin_granted` in Changes.

Out of scope for the smoke: Okta Workflows, write-back, Identity Governance.
Tear down by revoking the token and deleting the connector instance.

## Related

- `connectors/okta/README.md`
- [`connectors.md`](../connectors.md) (SDK, instance and secret handling, live smoke checklist)
- [Okta service-app guide](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)
- [Okta API token docs](https://help.okta.com/en-us/content/topics/security/api.htm)
- [Okta rate limits](https://developer.okta.com/docs/reference/rl-global-mgmt/)
