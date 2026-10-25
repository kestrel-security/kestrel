# Roadmap

Where Kestrel is, by capability, and what work is in progress. This page is
the list of open work; new bugs and feature requests go in
[GitHub issues](https://github.com/kestrel-security/kestrel/issues); long-term
direction is [`product.md`](product.md); decisions are in
[`decisions.md`](decisions.md).

**Legend:** ✅ largely done · 🔧 partial · ⬜ not started · — not planned for now

## Foundation

| Item | State |
|------|-------|
| Repository health (monorepo, lockfiles, gitignore, hygiene checks) | ✅ |
| Local development (Compose, `kestrel init --seed`, `kestrel demo up`) | ✅ |
| CI (lint, format, types, tiered tests, web build, dependency and secret scans) | ✅ |
| Authentication (opaque tokens, local login, 3-role RBAC) | ✅ (ADR-0008) |
| Tenant model (`org_id`, single-org UX) | 🔧 (schema ready; Postgres RLS deferred, maintainer decision) |
| Database + migrations | ✅ |
| Logging + observability | 🔧 (structured logs ✅; Prometheus + optional OTLP ✅; no shipped Grafana boards) |
| Secure secrets handling | 🔧 (envelope crypto ✅; secrets UI ✅; KMS ⬜) |

## First end-to-end release

| Item | State |
|------|-------|
| One high-quality connector (GitHub) | ✅ (fixtures + live PAT / GitHub App) |
| Asset / identity / configuration ingestion | 🔧 (identities, groups, roles, resources, grants, settings ✅; depth varies by connector) |
| Policy packs | ✅ (Python policies; per-application packs) |
| Findings + finding detail | ✅ |
| Investigation | 🔧 (finding workbench, evidence, provenance ✅; attack-path narrative partial) |
| Remediation status | 🔧 (status, exceptions, playbooks, verify ✅; no write-back: connectors are read-only by design) |

## Extensible platform

| Item | State |
|------|-------|
| Connector SDK | ✅ |
| Custom connector support | 🔧 (scaffold, `examples/custom-connector` and Integrations → Custom ✅; generic HTTP ⬜) |
| Versioned schemas | 🔧 (`schema_version` fields; evolution process maturing) |
| Policy authoring | ✅ (workbench + Monaco + grounded AI generate + packs) |
| Policy testing | ✅ (fixtures, dry-run, evaluate now) |
| Integration health | 🔧 (Integration health page + run history; SLO polish ⬜) |
| Incremental sync | ✅ (`since` in the protocol; per-object-type audit-log cursors in `kestrel.sync.cursors`; inventory is re-read in full each sync) |
| Relationship graph (data plane) | ✅ (Postgres graph, snapshots) |
| Live connectors | 🔧 (GitHub ✅; Google Workspace ✅; Okta ✅; Slack incl. Enterprise Grid ✅; live-tenant smoke pending across the four connectors) |

## Operational SSPM

| Item | State |
|------|-------|
| Cross-app access mapping | ✅ (graph, identity correlation materialized in `identity_links`, federated edges, Explore, Identities pages, cross-app policies, toxic-combination findings) |
| Change detection | ✅ (per-sync snapshots, classified feed, search, before/after evidence; DEC-024) |
| Tenant configuration posture | 🔧 (`setting` object + policies; coverage varies) |
| Remap control mappings to NIST CSF 2.0 | ⬜ (packs map to NIST CSF 1.1 subcategories such as `PR.AC-4` today) |
| Shadow SaaS discovery | — |
| Evidence collection | ✅ (finding evidence + provenance browser) |
| Notifications | ✅ (outbound webhooks, in-app inbox, email, weekly watched-findings digest) |
| Ticketing integrations | ✅ (GitHub Issues / Jira Cloud adapters, Settings UI, create from a finding) |
| Remediation workflows | 🔧 (playbooks + verify ✅; write-back ⬜) |
| Dashboards | ✅ (multi-board, metric DSL, daily posture-trend widget, PDF export, scheduled email) |
| GitOps plan/apply | ✅ |
| Scheduled sync / continuous monitoring | ✅ |
| Demo / time-to-value | ✅ (four generated tenants + drift timeline + `kestrel demo verify`) |
| Product surface | ✅ (Dashboard · Integrations · Identities · Explore · Changes · Policies · Findings + Settings) |

## Platform maturity (org-scale operations)

| Item | State |
|------|-------|
| SSO / SCIM | ⬜ |
| Advanced RBAC (beyond 3 fixed roles) | ⬜ |
| Audit export | ✅ |
| Multi-organization management | ⬜ (schema prepared) |
| Hardened deployment controls / HA | ⬜ |
| Data residency considerations | ⬜ |
| KMS-backed secrets | ⬜ |
| Signed releases | ⬜ |

## Ecosystem

| Item | State |
|------|-------|
| Plugin registry | ⬜ |
| Shared connectors / policies | 🔧 (four first-party connectors + one custom example; custom connector directory ✅) |
| Managed connector certification | ⬜ |
| Developer portal | ⬜ |
| API discovery → connector generation | ⬜ (vision) |
| Optional SQL detections alongside Python | ⬜ (vision; Python remains the default) |

## Active programs

### GitHub connector depth

Make GitHub the reference connector rather than the oldest one. When the
program started it collected nine object types: membership and repo-access
inventory, not GitHub security posture. It now collects the org
security surface (Actions permissions, runners and runner groups, secrets and
variables metadata, org webhooks, installed Apps, SSO credential
authorizations, rulesets, security managers, custom roles, invitations, PAT
requests, Copilot, packages, IP allow list), risk-tiered per-repository posture attached to each repository as
subject-scoped settings, and a curated audit-log taxonomy read through a
cursor. Still open: the enterprise layer, GraphQL batching for the repository
fan-out, the inbound webhook receiver, and the new graph shapes in Explore.

**Bar:** complete critical-settings coverage at org, repo, and enterprise
level; near-real-time detection of critical change with honest latency claims;
coverage that degrades visibly (a plan- or permission-gated family reduces the
run, never fails it, and never reads as deletion); GitHub App as the
recommended credential; `packs/github-posture` with fixtures for every policy
and `fixtures/changed/` pairs for every claimed change class.

**Decisions:**

- Real time is cursored fast polling plus a webhook receiver used as a
  *trigger*, not streaming. GitHub's audit-log streaming sinks are
  customer-owned and no faster than the REST API, and would still need a
  polling reconciler. Webhooks are seconds-latency, cover configuration
  changes the audit log surfaces poorly, and work on every plan while the
  audit-log API is Enterprise Cloud only. The receiver synthesizes no events; it
  verifies, records, and enqueues a targeted re-collection, so DEC-024 holds.
- GitHub App is the recommended auth for deep coverage. Reading runner groups
  and webhooks with a classic PAT requires write-shaped scopes that collide with
  read-only enforcement; Apps express the same reads as granular read-only
  permissions.
- Repo posture is risk-tiered. Deep posture is ~6 calls per repo; the default
  scan covers public and internal repos plus repos with an outside collaborator
  or a direct admin grant, with a configurable override, a cap, and truncation
  reported in run status.
- GHAS stays in the posture lane: enablement per org/repo and open
  secret-scanning, Dependabot, and code-scanning alert counts, never alert
  contents.

**Non-goals:** write-back remediation, code content, CI log analysis, PR review
workflow, full GitHub Enterprise Server support (a configurable base URL makes
GHES work opportunistically).

The remaining items are open. To pick one up, open an issue describing the
approach first.

### Connector completeness

Finish GitHub, Okta, and Slack, the three connectors this program started
with, to one bar, defined in [`connectors.md`](connectors.md#the-connector-bar),
and make every admin-driven change on those platforms land in `/changes` with
the actor attached. Google Workspace arrived after the program was scoped and
is held to the same bar; its state is in the capability table above. DEC-024
is unchanged: the actor overlay is additive on diff rows.

| Item | State |
|------|-------|
| Incremental sync (cursors, `since`, events-only schedule) | shipped |
| Policy platform (`resource` loader, event attributes, subject-scoped settings) | shipped |
| Degradation parity: Okta and Slack record `skipped_object_types` | shipped |
| Audit rows out of the Changes feed | shipped |
| Manifest to normalizer entity-mapping contract | shipped |
| Audit actor overlay on change rows | shipped |
| Change-class coverage for all three connectors | open |
| Stale graph edges pruned on a complete run | shipped |
| `/changes` feed tests and scan-cap correctness | shipped |
| GitHub depth (org surface, repo posture, audit taxonomy, pack) | shipped; enterprise layer, GraphQL batching, webhook receiver open |
| Okta depth: authentication and session policy, perimeter and automation | shipped; privilege model and System Log depth open |
| Slack depth: auth governance, channel and data governance, apps, log depth | open |
| Live smoke on all three real tenants | open |
| Toxic-combination findings, reconciled after every evaluation | shipped |
| Cross-app pack expansion (separation of duties, orphans) | open |

Exit criteria: each of the three connectors satisfies all eight bar criteria; a
scope-gated tenant degrades visibly on every connector instead of showing
phantom revocations; and a staged admin grant appears in `/changes` exactly
once, with the audit actor attached.

### AI finding assist

Policy drafting already has an AI path in the workbench. Findings still require
the operator to synthesize evidence, remediation text, and context by hand. The
program ships a narrow, trustworthy assist that never changes finding status or
invents evidence.

**Bar:** **Explain** and **Suggest remediation steps** actions on finding
detail (Analyst and above). Model input is bounded to finding title, severity,
status, policy slug and remediation text, evidence fields, and subject labels;
no secrets and no unrestricted `raw_source`. Output is labeled "AI draft —
verify against evidence" and never auto-resolves, assigns, or creates tickets.
Reuses the org LLM settings (OpenAI / Anthropic) or the `KESTREL_LLM_*`
environment, as policy generate does, and reports plainly when no model is
configured. Rate-limited on the expensive tier. Secret-like
keys are stripped from anything sent to the model.

**Non-goals:** autonomous investigation agents, chat that can mutate inventory
or call connectors, replacing deterministic policy evaluation, cross-finding
case management.

Not started.

### Custom connectors

Operators connect an internal application from Integrations → Custom. The
`examples/custom-connector` package proves the path; plugin-directory
discovery lets a new package appear without a Dockerfile change; a generic
HTTP / OpenAPI connector is the later step for apps that should not need a
Python package (DEC-022).

### Changes as a black-box recorder

Every successful sync is a full inventory snapshot and `/changes` is the
classified diff against the previous one (DEC-024). Identity-aware search,
noise suppression, the connector change-coverage contract, and the audit-actor
overlay on change rows have shipped.
