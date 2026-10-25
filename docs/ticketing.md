# Ticketing adapters

Kestrel can open tracker issues from findings ([`findings.md`](findings.md)) via a **TicketProvider**
protocol (entry-point discovery group `kestrel.ticket_providers`, plus built-ins).

## Built-in providers

| Provider id | Tracker | Create API |
|-------------|---------|------------|
| `github_issues` | GitHub Issues | `POST https://api.github.com/repos/{owner}/{repo}/issues` |
| `jira_cloud` | Jira Cloud | `POST {base_url}/rest/api/3/issue` |

ServiceNow and bidirectional status sync are **not implemented** (deferred).

## Secrets

API tokens are envelope-encrypted with `KESTREL_MASTER_KEY` the same way webhook
signing secrets are (ADR-0004). Plaintext is accepted only on create or
`POST /ticket-integrations/{id}/rotate-token` — never returned on list/detail.

Jira `base_url` must be HTTPS and pass the connector SSRF guard (no loopback /
link-local / private ranges). GitHub uses the fixed `api.github.com` host;
config is only `owner/repo`.

## Operator flow

1. Admin: **Settings → Ticketing** → create a GitHub or Jira integration.
2. Analyst: finding detail → **Tickets** → pick integration → Create ticket (or Dry-run).
3. Kestrel builds the finding handoff markdown as the issue body, calls the
   provider, stores a `finding_tickets` row (URL + external id), appends an
   investigation note with the URL, and audits `finding.ticket_created`.

## UI

- **Settings → Ticketing** (Admin): list integrations; create GitHub (`owner/repo` + token) or Jira Cloud (`base_url` + email + API token); enable or disable; rotate token; delete. Plaintext tokens are never shown.
- **Finding detail → Tickets** (Analyst+): pick an enabled integration, optionally dry-run, create; the card lists `finding_tickets` with their URLs and deep-links to Settings when nothing is configured.

API: `GET`/`POST`/`PATCH`/`DELETE /ticket-integrations`, `GET /ticket-integrations/providers`, `POST /ticket-integrations/{id}/rotate-token`, `GET`/`POST /findings/{id}/tickets`. Not implemented: ServiceNow, bidirectional status sync, bulk create from the findings table.

URL-template “open create form” links (no API / no secrets) remain available
via Copy for ticket / handoff download.

## Dry-run

`POST /findings/{id}/tickets` with `{"dry_run": true}` returns a synthetic URL
without writing rows and without outbound HTTP (providers honor `dry_run`).

## Caps

At most **10** tickets may be created per finding (noise / abuse guard). Bulk
create is not in this slice.

## Extending

Register additional providers via the `kestrel.ticket_providers` entry-point
group. Implementations must accept an injectable `httpx.Client` for tests and
must never log credentials.
