# Findings

A finding is a policy saying something is wrong about one subject in one
application, with the evidence that produced it and the remediation the policy
author wrote. Findings open and resolve automatically as syncs and evaluations
run; operators triage them from `/findings`.

## Lifecycle

| Status | Meaning |
|--------|---------|
| `open` | The policy currently matches the subject |
| `resolved` | The subject no longer matches after a later evaluation (auto-resolved), the policy was disabled, or an operator resolved it |
| `exception` | An accepted risk recorded as an `Exception_` with a reason and optional expiry |
| `muted` | Snoozed with a required expiry; distinct from an exception |
| `suppressed` | Hidden by an operator without a formal exception |

Subjects (`FindingSubjectType`) are `identity`, `resource`,
`oauth_application`, `setting`, `event`, and `application`. Toxic-combination
system findings are reconciled from the signals of other open findings. Open
and resolve events fan out to [webhooks](api.md#webhooks) and to watchers.

### Reconciliation

Each evaluation reconciles a policy's matches against the **latest
non-resolved finding per (policy, subject)**, across every version of the
policy (`kestrel.findings.lifecycle`):

- **New match, no finding:** a finding opens, with `finding.opened` webhooks
  and notifications.
- **Match on an `open` finding:** `last_seen_at` and evidence are refreshed.
- **Match on a `muted`, `suppressed` or `exception` finding:** `last_seen_at`
  and evidence are refreshed, the status is kept, and nothing is sent. Triage
  is never undone by a sync.
- **An `open` finding no longer matches:** it auto-resolves, with
  `finding.resolved` webhooks and notifications. Triaged findings are left as
  they are, so a recurrence lands on the same triaged finding.
- **Policy-scoped exceptions** (`Exception_` with no `finding_id`, as written
  by [GitOps](gitops.md)) apply while unexpired: new matches are recorded as
  `exception` findings without a `finding.opened` event, and matching `open`
  findings move to `exception`.
- **Duplicates** left by pre-release builds (two non-resolved findings for one
  policy and subject) are merged into the latest: notes, tickets, watchers,
  finding exceptions, the assignee and any triage state move to it, and the
  older one resolves with a `finding.auto_resolved` audit row.

Publishing or rolling back a custom policy version, and re-installing a pack,
re-point the policy's non-resolved findings to the new current version (with
its severity) instead of opening new ones. Disabling a policy, or a pack,
resolves its non-resolved findings, each with a `finding.auto_resolved` audit
row whose reason is `policy_disabled` (shown on the finding's activity
timeline); the API also sends `finding.resolved` webhooks for them.

### Expiry

Every 5 minutes the worker's beat runs `kestrel.findings.reopen_expired_deferrals`:

- a `muted` finding whose `muted_until` has passed reopens;
- an `exception` finding reopens once every exception covering it (its own,
  and any policy-scoped one for its policy) has expired. A finding moved to
  `exception` by a plain status change, with no `Exception_` row, has nothing
  to expire and stays put.

A reopen sends `finding.opened` webhooks and notifications, like a manual
reopen, and records a `finding.auto_reopened` audit row (reason
`mute_expired` or `exception_expired`). If the subject no longer matches, the
next evaluation resolves it.

### When evaluation runs

A full or degraded sync evaluates every enabled policy. The audit-log poll
(an incremental run every 5 minutes) evaluates every policy only when it
changed inventory; when it only stored new activity, it evaluates only
`RESOURCE_TYPE=event` policies, and when it brought nothing new it evaluates
nothing. Evaluations of one org are serialized by a Postgres advisory lock, so
two syncs finishing together reconcile one after the other against current
data. Old `policy_evaluations` rows are pruned with
`kestrel retention prune-policy-evaluations` (see
[data retention](operations/data-retention.md)).

### Paging

`GET /findings` pages on `first_seen_at` (then `id`), behind severity in the
default order. `last_seen_at` changes on every evaluation, so it is never a
cursor key. `sort=newest` orders purely by first detection; `sort=last_seen`
is accepted as an alias.

## Triage surface

`/findings` is search-first: one command bar with free text over title,
policy slug, and subject label, plus tokens that map onto `GET /findings`
parameters:

| Token | Meaning |
|-------|---------|
| `severity:high` | `low` / `medium` / `high` / `critical` |
| `status:open` | Any status above |
| `policy:okta-admin-without-mfa` | Policy slug |
| `assignee:me` / `assignee:unassigned` | Ownership |
| `age:>7` | Days open |

Active filters are removable chips and live in the URL, so a view is
shareable. **Views** save the current chip state as a preset
(`GET`/`POST`/`PATCH`/`DELETE /findings/presets`), and the queues (open,
unassigned, mine) are one click away (`GET /findings/queues`). The table
supports bulk status and assignment changes (`POST /findings/bulk`) and CSV or
JSON export (`GET /findings/export`) with the same filters. The parser lives in
`apps/web/src/lib/findings-search.ts`; the Changes feed reuses its grammar.

## Finding detail

`GET /findings/{id}` and the detail page bring together everything an analyst
needs without leaving the page:

- **Subject card** with the application and tenant context, and the policy's remediation text and compliance mappings.
- **Evidence** rows from the policy's `evidence()` merged with baseline fields from the subject, each deep-linked to the entity, plus the **provenance browser** (`GET /findings/{id}/provenance`): the subject's stored `raw_source` with secret-looking keys redacted, a tombstone when the payload was trimmed by retention, and an honest `truncated` flag for oversized payloads. It never returns connector secrets.
- **Attack path** (`GET /findings/{id}/attack-path`) over real graph edges from the subject to privileged roles and sensitive resources, and **blast radius** neighbors with export (`GET /findings/{id}/blast-radius/export`).
- **Related findings** on the same subject, the same-policy cohort, and the subject's activity timeline.
- **Notes** (`GET`/`POST /findings/{id}/notes`, append-only) and **watchers** (`GET`/`POST`/`DELETE /findings/{id}/watch`; `GET /findings/watched`; see [Notifications](#notifications)).
- **Actions:** change status or assignee (`PATCH /findings/{id}`), record an exception (`POST /findings/{id}/exceptions`), mute or unmute with an expiry (`POST /findings/{id}/mute`, `/unmute`), **verify** (`POST /findings/{id}/verify`: a policy dry run for this subject only, without mutating status), and create a ticket.

Expiring exceptions and mutes have their own review queues
(`GET /findings/exceptions/expiring`, `GET /findings/mutes/expiring`); once
expired they are reopened automatically (see [Expiry](#expiry)).

## Handoff and tickets

`GET /findings/{id}/handoff?format=markdown|json` produces a paste-ready
remediation package (finding, subject, policy, evidence, playbook, attack
path) for Jira, Linear, or chat. Optional `github_repo=owner/repo` and
`jira_base_url=` parameters add pre-filled "create issue" URLs; both are
SSRF-checked and involve no outbound call.

One-click ticket creation (`POST /findings/{id}/tickets`,
`GET /findings/{id}/tickets`) goes through a configured `TicketIntegration`
(GitHub Issues or Jira Cloud) and records the ticket on the finding. Setup and
provider details: [`ticketing.md`](ticketing.md).

## Notifications

Personal notifications are per operator and separate from the org's outbound
webhooks (Settings → Webhooks) and from muting a finding.

- **Events:** a finding opened or resolved, and an outbound webhook delivery
  failing (first attempt only, so retries do not repeat it).
- **Who gets them:** every active operator whose preferences match: finding
  events enabled, severity at or above their minimum, event type not muted.
  Watching a finding overrides those filters for that finding. Each channel's
  on/off switch always applies.
- **In-app:** the bell in the sidebar shows the unread count and recent
  notifications, each linked to its finding or webhook. API:
  `GET /notifications` (cursor-paginated, `unread_only=true`),
  `GET /notifications/unread-count`, `POST /notifications/{id}/read`,
  `POST /notifications/read-all`. An operator only ever sees their own.
- **Email:** the same events, sent after the change commits through the
  organization's mail server, which an admin sets at Settings → Email (or the
  `KESTREL_SMTP_*` default, see [`deployment.md`](deployment.md)). Events
  from one change are batched into one email per operator. Links use
  `APP_URL`. With no mail server, no email is sent and Settings →
  Notifications says so.
- **Watched-findings digest:** the worker's beat checks hourly and emails each
  watcher with email enabled at most once a week: findings still open, resolved
  in the last 7 days, and active in the last 7 days. Weeks with no changes are
  skipped. Each send is recorded as a `notification.watch_digest_sent` audit
  event. `POST /findings/watched/digest-preview` returns the digest, whether
  the next run would send it, and why not.

Preferences: `GET`/`PATCH /notification-preferences`, or Settings →
Notifications in the web UI.

## Playbooks and verification

Each policy's remediation text renders as a playbook on the finding. After the
operator changes the SaaS configuration, **Verify** dry-runs the policy against
current inventory and reports whether this subject is still among the matches
(checked against every match, not just the first page the dry run returns); the next sync
and evaluation resolve the finding for real. There is no write-back: Kestrel
does not change anything in the connected application.

## Where findings come from

- **Posture policies** over inventory rows (identities, grants, settings, OAuth applications, application instances).
- **Event policies** (`RESOURCE_TYPE=event`) over provider audit rows within the lookback window.
- **System findings** for toxic combinations of other open findings.

Policies, packs, and evaluation: [`policies.md`](policies.md). The difference
between a finding and a change: [`changes.md`](changes.md).
