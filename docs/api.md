# HTTP API

Every product surface is served by the FastAPI application under
`/api/v1/*`. Interactive OpenAPI docs are at `/docs` on a running API
(`http://localhost:8010/docs` locally). The route tables at the bottom of
this page are generated from that schema and verified by a test, so they
cannot name a route the application does not serve. Conventions the routes
share are in [`api-guidelines.md`](api-guidelines.md).

## Authentication

Every `/api/v1/*` route except `POST /api/v1/auth/login` requires
`Authorization: Bearer <token>`. Two token kinds share the header
([ADR-0008](adr/0008-opaque-tokens-for-operator-auth.md)):

- **Session tokens** from `POST /api/v1/auth/login`, which the web app stores in an `httponly` cookie and forwards as the header on the server side.
- **API tokens** from `POST /api/v1/api-tokens` or `kestrel token create`, long-lived, revocable, for the CLI and automation.

Tokens are opaque; the server looks them up, never decodes them. Passwords
are hashed with Argon2id; five failed logins lock the account for fifteen
minutes and every failure returns the same response, so accounts cannot be
enumerated. `GET /healthz` and `GET /metrics` are outside the prefix and
unauthenticated; restrict `/metrics` at the network edge in production.

```bash
TOKEN=$(curl -s -X POST http://localhost:8010/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@kestrel.local","password":"kestrel-dev-password"}' | jq -r .token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8010/api/v1/findings
```

## Authorization and tenancy

Roles are `read_only` < `analyst` < `admin`. Read routes accept any role;
mutating routes declare a minimum with `require_role` (analysts change
findings, exceptions, connector instances, and syncs; admins manage
operators, webhooks, ticket integrations, AI settings, and read the audit
log). Every query is scoped to the caller's organization; an object that
belongs to another org is a `404`, not a `403`.

## Errors

| Status | Meaning |
|--------|---------|
| `401` | Missing, malformed, invalid, expired, or revoked bearer token |
| `403` | Authenticated, but the operator's role is below the route's minimum, or a state-changing request came from a disallowed `Origin` |
| `404` | Not found, or not owned by the caller's org |
| `409` | Conflict (for example creating a duplicate connector instance) |
| `422` | Request validation failure in FastAPI's standard shape |
| `429` | Rate limited; see below |
| `503` | No organization configured yet (`kestrel init` has not run) |

## Pagination

Collection endpoints that can grow with collected data (`GET /identities`,
`GET /findings`, `GET /audit-log`, `GET /changes`) use keyset (cursor)
pagination. They accept `limit` (default 50, maximum 200, values above the
maximum are clamped, `limit < 1` is `422`) and `cursor`, and return:

```json
{ "items": [ ... ], "next_cursor": "eyJ0cyI6Ii4uLiIsImlkIjoiLi4uIn0" }
```

Pass `next_cursor` back as `?cursor=` to fetch the next page; it is `null`
on the last page. Cursors are opaque base64url strings whose encoding may
change without notice; a malformed cursor is `422`. Ordering is
`(timestamp DESC, id DESC)` with the id as a tiebreaker, so concurrent syncs
shift what comes next instead of skipping or repeating rows. Filters apply
before the limit. Lists bounded by configuration rather than data volume
(policies, packs, connector instances, webhooks) return bare arrays.

## Rate limiting

A fixed-window limiter runs in front of `/api/v1/*`, backed by Redis when
`REDIS_URL` is reachable and by process memory otherwise. Requests are
classified into tiers:

| Tier | Applies to | Default per window |
|------|------------|--------------------|
| `login` | `POST /api/v1/auth/login`, keyed by client IP | 20 |
| `expensive` | `POST` to policy validate / test / dry-run / evaluate / fixtures-from-matches, `POST /api/v1/policies/generate`, and `POST /api/v1/connector-instances/{id}/sync`, keyed by token | 30 |
| `default` | Everything else under `/api/v1`, keyed by token | 300 |
| `exempt` | `/healthz`, `/metrics`, `/docs`, `/openapi.json` | none |

The window is 60 seconds. A limited request returns `429` with a
`Retry-After` header. Tune with `KESTREL_RATE_LIMIT_ENABLED`,
`KESTREL_RATE_LIMIT_WINDOW_SECONDS`, `KESTREL_RATE_LIMIT_DEFAULT`,
`KESTREL_RATE_LIMIT_EXPENSIVE`, `KESTREL_RATE_LIMIT_LOGIN`, and
`KESTREL_RATE_LIMIT_BACKEND` ([`operations/rate-limiting.md`](operations/rate-limiting.md)).

## Origin check

Bearer auth is not cookie auth, so classic CSRF does not apply to the API;
the web app owns the session cookie and has its own protections. As a
backstop for the case the API port is reachable from a browser,
`ALLOWED_ORIGIN` (comma-separated) makes the API return `403` for `POST`,
`PUT`, `PATCH`, and `DELETE` requests whose `Origin` header is present and
not allow-listed. Unset, the check is a no-op.

## Webhooks

Admins register HTTPS endpoints (`POST /api/v1/webhooks`); each endpoint
gets a signing secret shown once at creation and on
`POST /api/v1/webhooks/{id}/rotate-secret`. Endpoint URLs must use
`https` (create, update, and again before every delivery): plain `http://`
is refused unless the host is on `KESTREL_CONNECTOR_URL_ALLOWLIST`, for local
testing. They also pass the same SSRF guard as connector configuration. Finding lifecycle events are
delivered asynchronously by the worker with retries; history is at
`GET /api/v1/webhooks/{id}/deliveries` and a failed delivery can be replayed
with `POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/retry`.
A failed delivery's `error_message` is a concise summary, not the receiver's
response body: `HTTP <status>: <excerpt>`, where the excerpt is the body's
text with HTML tags removed and whitespace collapsed, capped at about 200
characters. Failure notifications (in-app and email) show the same summary.

Event types: `finding.opened`, `finding.resolved`. Headers on every delivery:

| Header | Value |
|--------|-------|
| `X-Kestrel-Event` | The event type |
| `X-Kestrel-Delivery` | The delivery id (idempotency key for receivers) |
| `X-Kestrel-Timestamp` | Unix seconds when the request was signed |
| `X-Kestrel-Signature` | `v1=<hex>`: HMAC-SHA256 over `"{timestamp}." + raw_body` with the endpoint secret |

Receivers should verify the signature with a constant-time comparison and
reject deliveries whose timestamp is more than five minutes from their own
clock. `kestrel.webhooks.signing.verify_signature` is the reference
implementation.

## Routes

Generated; regenerate with `uv run python scripts/gen-api-docs.py` after
adding or changing a route (`make api-docs`). `tests/unit/test_api_docs.py`
fails when this block is stale or when any `METHOD /path` mentioned anywhere
in this document is not served. Request and response bodies are in the
OpenAPI schema at `/docs`; the feature pages under `docs/` explain the
behavior behind each group.

<!-- BEGIN GENERATED ROUTES -->

_174 operations, generated from the application's OpenAPI schema by `scripts/gen-api-docs.py`. Do not edit by hand._

### Auth

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/auth/change-password` | Change the caller's password and sign out their other sessions |
| `POST` | `/api/v1/auth/login` | Login |
| `POST` | `/api/v1/auth/login/mfa` | Finish a sign-in with a TOTP or recovery code |
| `POST` | `/api/v1/auth/logout` | Logout |
| `GET` | `/api/v1/auth/me` | The signed-in operator. Also answers a session limited to MFA setup, |
| `GET` | `/api/v1/auth/mfa` | Whether the caller has two-factor authentication on, and how many recovery codes are left |
| `POST` | `/api/v1/auth/mfa/activate` | Turn MFA on with a first code from the authenticator. Returns the |
| `POST` | `/api/v1/auth/mfa/disable` | Turn MFA off. Needs the password and a current code, and is refused |
| `POST` | `/api/v1/auth/mfa/recovery-codes` | Replace every recovery code with a fresh set (shown only this once) |
| `POST` | `/api/v1/auth/mfa/setup` | Start enrolment: a new secret to add to an authenticator app |

### Operators

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/operators` | List Operators |
| `POST` | `/api/v1/operators` | Create Operator |
| `GET` | `/api/v1/operators/{operator_id}` | Get Operator |
| `PATCH` | `/api/v1/operators/{operator_id}` | Patch Operator |
| `POST` | `/api/v1/operators/{operator_id}/mfa/reset` | Remove another operator's second factor (lost device) and end their sessions |
| `POST` | `/api/v1/operators/{operator_id}/set-password` | Set Password |
| `GET` | `/api/v1/org/security` | Get Security |
| `PATCH` | `/api/v1/org/security` | Update Security |

### API tokens

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/api-tokens` | List Tokens |
| `POST` | `/api/v1/api-tokens` | Create Token |
| `DELETE` | `/api/v1/api-tokens/{token_id}` | Revoke Token |

### Dashboard (home)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/dashboard` | Org-scoped posture overview for the operator home dashboard |
| `POST` | `/api/v1/dashboard/first-run/dismiss` | Hide the getting-started checklist for the calling operator until restored |
| `POST` | `/api/v1/dashboard/first-run/restore` | Show the getting-started checklist again for the calling operator |
| `GET` | `/api/v1/dashboard/layout` | Per-operator widget layout (defaults when unset) |
| `PUT` | `/api/v1/dashboard/layout` | Save the calling operator's dashboard widget layout |
| `POST` | `/api/v1/dashboard/layout/reset` | Clear saved layout so the default overview is restored |

### Dashboards (boards)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/dashboards` | List Dashboards |
| `POST` | `/api/v1/dashboards` | Create Dashboard |
| `POST` | `/api/v1/dashboards/pin-home` | Pin Home |
| `GET` | `/api/v1/dashboards/presets` | Get Presets |
| `POST` | `/api/v1/dashboards/query/preview` | Query Preview |
| `GET` | `/api/v1/dashboards/{dashboard_id}` | Get Dashboard |
| `PATCH` | `/api/v1/dashboards/{dashboard_id}` | Patch Dashboard |
| `DELETE` | `/api/v1/dashboards/{dashboard_id}` | Remove Dashboard |
| `POST` | `/api/v1/dashboards/{dashboard_id}/duplicate` | Duplicate |
| `POST` | `/api/v1/dashboards/{dashboard_id}/export` | Export |
| `PUT` | `/api/v1/dashboards/{dashboard_id}/layout` | Put Layout |
| `GET` | `/api/v1/dashboards/{dashboard_id}/schedules` | Get Schedules |
| `POST` | `/api/v1/dashboards/{dashboard_id}/schedules` | Post Schedule |
| `PATCH` | `/api/v1/dashboards/{dashboard_id}/schedules/{schedule_id}` | Patch Schedule |
| `DELETE` | `/api/v1/dashboards/{dashboard_id}/schedules/{schedule_id}` | Remove Schedule |
| `POST` | `/api/v1/dashboards/{dashboard_id}/set-default` | Set Default |
| `POST` | `/api/v1/dashboards/{dashboard_id}/widgets` | Create Widget |
| `PATCH` | `/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}` | Patch Widget |
| `DELETE` | `/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}` | Remove Widget |

### Changes

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/changes` | Classified changes for the org, most significant first |
| `GET` | `/api/v1/changes/classes` | Vocabulary for building filters without hardcoding it in the client |

### Graph

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/graph/edges/{edge_id}` | Graph Edge |
| `GET` | `/api/v1/graph/nodes/{node_id}/context` | Graph Context |
| `GET` | `/api/v1/graph/nodes/{node_id}/neighbors` | Bounded-depth neighbor expansion (nodes + edges) |
| `GET` | `/api/v1/graph/nodes/{node_id}/paths` | Shortest paths from (out) or to (in) this node, with hop access_path |
| `GET` | `/api/v1/graph/resolve` | Map an entity PK to its graph_nodes.id (different concepts — ADR-0003) |
| `GET` | `/api/v1/graph/search` | Label search for the Explore picker |

### Identities

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/identities` | List Identities |
| `GET` | `/api/v1/identities/correlated` | Cross-connector identity clusters sharing a normalized email |
| `GET` | `/api/v1/identities/{identity_id}` | Get Identity |
| `GET` | `/api/v1/identities/{identity_id}/access` | Identity Access |
| `GET` | `/api/v1/identities/{identity_id}/overview` | Everything the identity detail page shows, in one round trip |

### Search

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/search` | Grouped entity search over identities, findings, and policies, for |

### Findings

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/findings` | Sorted by `severity DESC, first_seen_at DESC, id DESC` by default -- |
| `POST` | `/api/v1/findings/bulk` | Apply the same status and/or assignment change to many findings |
| `GET` | `/api/v1/findings/exceptions/expiring` | Exception expiry review queue for findings in exception status |
| `GET` | `/api/v1/findings/export` | Auditor/SecOps export of findings matching list filters (capped) |
| `GET` | `/api/v1/findings/mutes/expiring` | Mute/snooze expiry review queue — distinct from exceptions |
| `GET` | `/api/v1/findings/presets` | Per-operator saved findings filter presets |
| `POST` | `/api/v1/findings/presets` | Create or upsert a named filter preset for the calling operator |
| `PATCH` | `/api/v1/findings/presets/{preset_id}` | Rename, update filters, and/or favorite a preset owned by the caller |
| `DELETE` | `/api/v1/findings/presets/{preset_id}` | Remove Finding Preset |
| `POST` | `/api/v1/findings/presets/{preset_id}/use` | Bump last_used_at when the operator applies a preset in the UI |
| `GET` | `/api/v1/findings/queues` | SecOps ownership queues for open findings |
| `GET` | `/api/v1/findings/watched` | Findings the calling operator is watching |
| `GET` | `/api/v1/findings/watched/digest` | Structured watched-findings digest for the calling operator |
| `POST` | `/api/v1/findings/watched/digest-preview` | Preview the caller's watched-findings digest email. Sends nothing |
| `GET` | `/api/v1/findings/{finding_id}` | Get Finding |
| `PATCH` | `/api/v1/findings/{finding_id}` | Patch Finding |
| `GET` | `/api/v1/findings/{finding_id}/attack-path` | Ordered attack-path hops over existing graph edges |
| `GET` | `/api/v1/findings/{finding_id}/blast-radius/export` | CSV/JSON export of blast-radius findings + graph subgraph |
| `POST` | `/api/v1/findings/{finding_id}/exceptions` | Create Exception |
| `GET` | `/api/v1/findings/{finding_id}/handoff` | Ticket / chat remediation package |
| `POST` | `/api/v1/findings/{finding_id}/mute` | Temporarily mute/snooze a finding with a required expiry |
| `GET` | `/api/v1/findings/{finding_id}/notes` | List investigation notes for a finding, newest first |
| `POST` | `/api/v1/findings/{finding_id}/notes` | Append an investigation note. Does not change finding status |
| `GET` | `/api/v1/findings/{finding_id}/provenance` | Subject raw_source browser for investigation |
| `GET` | `/api/v1/findings/{finding_id}/tickets` | List tickets created from this finding |
| `POST` | `/api/v1/findings/{finding_id}/tickets` | Create a tracker issue via TicketProvider and record the URL |
| `POST` | `/api/v1/findings/{finding_id}/unmute` | Clear mute and reopen the finding |
| `POST` | `/api/v1/findings/{finding_id}/verify` | Re-check remediation: dry-run policy for this subject |
| `GET` | `/api/v1/findings/{finding_id}/watch` | Whether the calling operator is watching this finding |
| `POST` | `/api/v1/findings/{finding_id}/watch` | Subscribe to in-app updates for this finding. Idempotent |
| `DELETE` | `/api/v1/findings/{finding_id}/watch` | Unsubscribe from this finding. Idempotent |

### Connectors

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/connector-instances` | List Connector Instances |
| `POST` | `/api/v1/connector-instances` | Create Connector Instance Route |
| `GET` | `/api/v1/connector-instances/health` | Integration health: summary counts + per-instance freshness |
| `GET` | `/api/v1/connector-instances/{connector_instance_id}` | Instance detail for the Builder edit UI: config + secret field status (no plaintext) |
| `PATCH` | `/api/v1/connector-instances/{connector_instance_id}` | Update non-secret settings (config / auth / sync mode / display name) |
| `DELETE` | `/api/v1/connector-instances/{connector_instance_id}` | Delete a connector instance and everything collected through it |
| `GET` | `/api/v1/connector-instances/{connector_instance_id}/runs` | List Runs |
| `PATCH` | `/api/v1/connector-instances/{connector_instance_id}/schedule` | Sets or clears (schedule_cron: null) an instance's periodic sync |
| `GET` | `/api/v1/connector-instances/{connector_instance_id}/secrets` | Secret field status only — never plaintext or ciphertext |
| `PUT` | `/api/v1/connector-instances/{connector_instance_id}/secrets` | Upsert envelope-encrypted secrets. Empty values are ignored (leave blank to keep) |
| `POST` | `/api/v1/connector-instances/{connector_instance_id}/sync` | Trigger Sync |
| `POST` | `/api/v1/connector-instances/{connector_instance_id}/test-connection` | Probe live/fixture credentials via collector.health_check() |
| `GET` | `/api/v1/connector-runs/{run_id}` | Sync run detail: object counts, errors, drift summary, and policy evaluations |
| `GET` | `/api/v1/connector-runs/{run_id}/changes` | Entity drift / change diff for a sync run |
| `GET` | `/api/v1/connectors` | Installed connector packages (entry-point discovery), with manifest |
| `POST` | `/api/v1/connectors/probe` | Test credentials the wizard has not saved yet |

### Policies

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/policies` | List installed policies with resource_type, open findings, and last eval |
| `POST` | `/api/v1/policies` | Create Policy |
| `GET` | `/api/v1/policies/authoring-contract` | Helpers, builtins, rules, idioms and row shapes a policy may use: the same contract the AI generate prompt uses |
| `POST` | `/api/v1/policies/dry-run-draft` | Evaluate unsaved Python policy source against live inventory without writing findings |
| `POST` | `/api/v1/policies/fixtures/from-matches` | Build fixture JSON from live matches for unsaved draft source |
| `POST` | `/api/v1/policies/generate` | Return an AI, template, or unconfigured draft — never persists or enables |
| `GET` | `/api/v1/policies/generate/catalog` | Connector field catalog, intent chips, and redacted live samples for the Workbench |
| `POST` | `/api/v1/policies/test-draft` | Fixture-test an unsaved draft (no policy id yet). Requires |
| `POST` | `/api/v1/policies/validate` | Compile + validate Python policy without persisting |
| `GET` | `/api/v1/policies/{policy_id}` | Get Policy |
| `PATCH` | `/api/v1/policies/{policy_id}` | Patch Policy |
| `DELETE` | `/api/v1/policies/{policy_id}` | Permanently delete a policy, its versions, evaluation history, and findings |
| `POST` | `/api/v1/policies/{policy_id}/dry-run` | Evaluate a policy (or optional draft source_text) against live inventory |
| `POST` | `/api/v1/policies/{policy_id}/evaluate` | Run the current policy version and reconcile findings |
| `GET` | `/api/v1/policies/{policy_id}/evaluations` | Recent PolicyEvaluation rows for this policy (newest first) |
| `GET` | `/api/v1/policies/{policy_id}/findings` | Open findings strip for policy detail |
| `GET` | `/api/v1/policies/{policy_id}/fixtures` | Return fixtures for Workbench prefill |
| `PUT` | `/api/v1/policies/{policy_id}/fixtures` | Save or clear custom policy fixtures. Pack policies → 400 |
| `POST` | `/api/v1/policies/{policy_id}/fixtures/from-matches` | Build fixture JSON from dry-run / live matches; optionally persist |
| `POST` | `/api/v1/policies/{policy_id}/fork` | Fork a pack policy into a new disabled custom policy |
| `POST` | `/api/v1/policies/{policy_id}/test` | Runs fixtures against the current saved version, or against an |
| `GET` | `/api/v1/policies/{policy_id}/versions` | List immutable PolicyVersion rows for this policy (newest first) |
| `POST` | `/api/v1/policies/{policy_id}/versions` | Create Policy Version |
| `POST` | `/api/v1/policies/{policy_id}/versions/{version_id}/activate` | Set ``current_version_id`` to a prior immutable version (custom only) |

### Packs

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/packs` | Lists packs discoverable under `KESTREL_PACKS_DIR` (default `./packs`) |
| `GET` | `/api/v1/packs/{name}` | Pack marketplace detail: policy titles/severities from disk |
| `GET` | `/api/v1/packs/{name}/coverage` | Get Pack Coverage |
| `POST` | `/api/v1/packs/{name}/disable` | Disable Named Pack |
| `POST` | `/api/v1/packs/{name}/enable` | Enable Named Pack |
| `POST` | `/api/v1/packs/{name}/install` | Installs (or re-installs) a catalog pack into the current org |
| `GET` | `/api/v1/packs/{name}/install-preview` | Diff on-disk pack policies vs org-installed (by slug) before install |

### Audit log

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/audit-log` | Most recent first (`created_at DESC, id DESC`). Cursor-paginated; |
| `GET` | `/api/v1/audit-log/export` | Auditor export of audit rows matching list filters (capped at EXPORT_AUDIT_MAX) |

### Webhooks

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/webhooks` | List Webhooks |
| `POST` | `/api/v1/webhooks` | Create Webhook |
| `GET` | `/api/v1/webhooks/{webhook_id}` | Get Webhook |
| `PATCH` | `/api/v1/webhooks/{webhook_id}` | Patch Webhook |
| `DELETE` | `/api/v1/webhooks/{webhook_id}` | Delete Webhook |
| `GET` | `/api/v1/webhooks/{webhook_id}/deliveries` | Get Deliveries |
| `POST` | `/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry` | Retry Webhook Delivery |
| `POST` | `/api/v1/webhooks/{webhook_id}/rotate-secret` | Rotate Webhook Secret |

### Ticket integrations

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/ticket-integrations` | List Ticket Integrations |
| `POST` | `/api/v1/ticket-integrations` | Create Ticket Integration |
| `GET` | `/api/v1/ticket-integrations/providers` | Built-in + entry-point TicketProvider ids |
| `GET` | `/api/v1/ticket-integrations/{integration_id}` | Get Ticket Integration |
| `PATCH` | `/api/v1/ticket-integrations/{integration_id}` | Patch Ticket Integration |
| `DELETE` | `/api/v1/ticket-integrations/{integration_id}` | Delete Ticket Integration |
| `POST` | `/api/v1/ticket-integrations/{integration_id}/rotate-token` | Rotate Ticket Integration Token |

### AI settings

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/settings/ai` | Get Ai Settings |
| `PUT` | `/api/v1/settings/ai` | Put Ai Settings |
| `DELETE` | `/api/v1/settings/ai` | Delete Ai Settings |

### Email settings

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/settings/email` | The mail server in force (saved here or from the environment) and the saved settings |
| `PUT` | `/api/v1/settings/email` | Save the organization's mail server; it overrides the environment's |
| `DELETE` | `/api/v1/settings/email` | Remove the saved mail server; email falls back to the environment, if set |
| `POST` | `/api/v1/settings/email/test` | Send a test message to the caller's own address through the mail server in force |

### Notification preferences

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/notification-preferences` | Get Notification Preferences |
| `PATCH` | `/api/v1/notification-preferences` | Patch Notification Preferences |

### Notifications

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/notifications` | The caller's notifications, newest first |
| `POST` | `/api/v1/notifications/read-all` | Mark every unread notification read. Returns how many changed |
| `GET` | `/api/v1/notifications/unread-count` | How many of the caller's notifications are unread |
| `POST` | `/api/v1/notifications/{notification_id}/read` | Mark one notification read. Idempotent; 404 for another operator's row |

### Resources

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/resources` | List Resources |
| `GET` | `/api/v1/resources/{resource_id}` | Get Resource |
| `PATCH` | `/api/v1/resources/{resource_id}/sensitivity` | Set Resource Sensitivity |

### Operational endpoints (no auth, outside /api/v1)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness plus the running build version, which a deploy pipeline can poll |
| `GET` | `/metrics` | Prometheus text exposition. Public like /healthz — restrict at the network edge in production |
| `GET` | `/readyz` | Readiness: can this process actually serve requests? |

<!-- END GENERATED ROUTES -->
