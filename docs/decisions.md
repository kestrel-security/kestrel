# Decision log

Index of architecture and product decisions. Accepted architecture decisions
have a full record under [`adr/`](adr/); product and sequencing decisions
without an ADR are recorded below. Proposals are marked and are **not**
approved until the maintainers accept them ([`GOVERNANCE.md`](../GOVERNANCE.md)). New records use
[`templates/decision-record.md`](templates/decision-record.md).

How to use this file:

1. Before an architectural change, search here and `adr/`.
2. If work would change an Accepted decision, open an issue proposing the
   change first; do not change the behaviour in the same pull request.
3. When the maintainers accept a proposal, add or update an ADR and set the
   status here.

## Index

| ID | Title | Date | Status | Record |
|----|-------|------|--------|--------|
| DEC-001 | Apache License 2.0 | 2026-07-21 | Accepted | below |
| DEC-002 | uv + pnpm monorepo, no cross-language orchestrator | 2026-07-21 | Accepted | [ADR-0001](adr/0001-monorepo-tooling.md) |
| DEC-003 | Python policies via RestrictedPython | 2026-07-30 | Accepted | [ADR-0009](adr/0009-python-policies.md) |
| DEC-003-legacy | Lark-based policy DSL, client-side evaluation | 2026-07-21 | Superseded by DEC-003 | [ADR-0002](adr/0002-legacy-policy-dsl-implementation-approach.md) |
| DEC-004 | Identity/access graph in PostgreSQL | 2026-07-21 | Accepted | [ADR-0003](adr/0003-graph-representation-in-postgres.md) |
| DEC-005 | Envelope encryption for connector secrets | 2026-07-21 | Accepted | [ADR-0004](adr/0004-secrets-storage-and-encryption.md) |
| DEC-006 | Protocol-based Connector SDK + entry-point discovery | 2026-07-21 | Accepted | [ADR-0005](adr/0005-connector-sdk-interface-design.md) |
| DEC-007 | Single-org deployment UX with `org_id` everywhere | 2026-07-21 | Accepted | [ADR-0006](adr/0006-multi-tenancy-approach.md) |
| DEC-008 | Celery + Redis for background jobs | 2026-07-21 | Accepted | [ADR-0007](adr/0007-job-worker-framework.md) |
| DEC-009 | One build — everything in this repository ships enabled | 2026-08-10 | Accepted | below |
| DEC-010 | Developer Certificate of Origin, no CLA | 2026-08-13 | Accepted | below |
| DEC-011 | Opaque tokens for operator auth, 3-role RBAC | 2026-07-22 | Accepted | [ADR-0008](adr/0008-opaque-tokens-for-operator-auth.md) |
| DEC-012 | Prometheus + optional OTLP, no APM vendor SDK | 2026-07-22 | Accepted | below |
| DEC-013 | Number not used | — | Withdrawn | below |
| DEC-014 | Workflow engine beyond Celery | 2026-07-22 | Proposed (retain Celery) | below |
| DEC-015 | Python modules are the policy format | 2026-07-30 | Accepted | [ADR-0009](adr/0009-python-policies.md) |
| DEC-016 | Graph storage stays Postgres unless evidenced | 2026-07-22 | Accepted | [ADR-0003](adr/0003-graph-representation-in-postgres.md) |
| DEC-017 | Withdrawn | 2026-08-03 | Withdrawn | below |
| DEC-018 | Reaffirm Apache-2.0 before public release | 2026-08-13 | Accepted | below |
| DEC-019 | Changes as a primary nav destination | 2026-08-10 | Accepted | below |
| DEC-020 | Withdrawn | 2026-08-10 | Withdrawn | below |
| DEC-021 | Explore as a primary nav destination | 2026-08-10 | Accepted; nav list superseded by DEC-026 | below |
| DEC-022 | Custom connectors stay Python packages; generic HTTP is additive | 2026-08-21 | Accepted | below |
| DEC-023 | Dashboard builder: multi-board + constrained metric DSL | 2026-08-24 | Accepted; DSL entities narrowed in 0.4.0 | below |
| DEC-024 | Snapshot-diff is the source of truth for Changes | 2026-08-24 | Accepted | below |
| DEC-025 | Four connectors, covered against published baselines | 2026-09-15 | Accepted | below |
| DEC-026 | Identities as a primary nav destination | 2026-09-04 | Accepted | below |
| DEC-027 | Withdrawn | 2026-09-18 | Withdrawn | below |
| DEC-028 | TOTP as the second factor, required per organization | 2026-10-07 | Accepted | below |
| DEC-029 | Admins configure the mail server in the app | 2026-10-07 | Accepted | below |

## Records without an ADR
### DEC-029: Admins configure the mail server in the app
- **Date:** 2026-10-07
- **Context:** Outbound email (notifications, watched-finding digests,
  dashboard schedules) could only be set up with `KESTREL_SMTP_*` environment
  variables, so turning email on or fixing a password meant editing the
  deployment and restarting it, out of reach of the people running Kestrel day
  to day.
- **Decision:** Each organization can save its own mail server at Settings →
  Email (admin only, audited): host, port, security (STARTTLS, SSL/TLS or
  none), optional credentials and the sender. The password is encrypted with
  the org key and never returned; it must be re-entered when the host, port or
  username changes, and credentials are refused without TLS. A saved, enabled
  server wins; otherwise the environment is a deployment-wide default, so
  deployments that configured email that way keep sending.
- **Alternatives considered:** dropping the environment variables (breaks
  existing deployments on upgrade for no gain); holding the mail host to the
  connector SSRF rule of public addresses only (internal relays and localhost
  sidecars are the normal way to send mail, so it would have pushed admins back
  to an environment allowlist).
- **Consequences:** Private and loopback hosts are allowed; link-local,
  cloud-metadata, multicast and reserved addresses are refused on save and
  checked again right before each connection. Every sender resolves the mail
  server per organization, and queued notification email carries its org.


### DEC-001: Apache License 2.0
- **Date:** 2026-07-21; reaffirmed 2026-08-13 (DEC-018)
- **Context:** A published security platform that accepts outside contributions needs a clear, OSI-approved license with an explicit patent grant.
- **Decision:** Apache License 2.0 (`LICENSE`, `NOTICE`).
- **Alternatives considered:** MIT (weaker patent language); AGPL-3.0 (network copyleft complicates adoption of a security tool inside many organizations); source-available licenses (not open source; rejected on principle).
- **Consequences:** Anyone may use, modify, and redistribute Kestrel, including in derived products. Inbound contributions use the DCO (DEC-010); inbound = outbound Apache-2.0. Any change to `LICENSE` needs explicit maintainer approval ([`GOVERNANCE.md`](../GOVERNANCE.md)).

### DEC-009: One build — everything in this repository ships enabled
- **Date:** 2026-08-10
- **Context:** A single build is simpler to test, review, and support than several variants of the same code.
- **Decision:** This repository produces one build, and every capability in it ships enabled. Org-scale features (SSO, multi-org, KMS) are tracked on the [roadmap](roadmap.md).
- **Consequences:** Contributions keep that property: new capabilities ship enabled.

### DEC-010: Developer Certificate of Origin, no CLA
- **Date:** 2026-07-22; accepted 2026-08-13
- **Context:** `CONTRIBUTING.md` needed an inbound contribution policy before wide external PRs.
- **Decision:** DCO 1.1. Contributors sign off commits (`git commit -s`). Inbound = outbound Apache-2.0. No CLA.
- **Alternatives considered:** CLA (heavier for contributors; its main benefit is enabling a later relicense, which is not planned); Apache inbound = outbound with no DCO (weaker provenance).
- **Consequences:** External PRs must include `Signed-off-by`. Relicensing this codebase later would need a new decision and likely a CLA before further external PRs.

### DEC-012: Prometheus + optional OTLP, no APM vendor SDK
- **Date:** 2026-07-22
- **Context:** Operators need request and job metrics and traces without a mandated APM vendor.
- **Decision:** Always-on Prometheus exposition (`/metrics`, worker scrape port); optional OpenTelemetry OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Instrumentation lives in `kestrel.observability`.
- **Alternatives considered:** Vendor APM agents; Pushgateway-only worker metrics; tracing always on.
- **Consequences:** Operators bring their own Prometheus and collector. Shipped Grafana boards are follow-up work.

### DEC-013: Number not used
- Number not used. It is kept so later IDs stay stable.

### DEC-014: Workflow engine beyond Celery
- **Date:** 2026-07-22 · **Status:** Proposed
- **Context:** Remediation approvals and multi-step investigations may eventually need richer workflows.
- **Decision:** *None yet.* Retain Celery (DEC-008). Do not introduce Temporal, Prefect, or similar without a decision record.

### DEC-017: Withdrawn
- Withdrawn before the first public release. The number is kept so later IDs stay stable.

### DEC-018: Reaffirm Apache-2.0 before public release
- **Date:** 2026-08-10; accepted 2026-08-13
- **Context:** Before publishing, the license choice was re-examined against copyleft and source-available alternatives.
- **Decision:** Keep Apache License 2.0 (DEC-001). Do not switch to AGPL or to any source-available license; the project's "open source" claim must stay accurate in the OSI sense.
- **Consequences:** Contributor model stays DCO (DEC-010). Changing `LICENSE` later needs explicit maintainer approval.

### DEC-019: Changes as a primary nav destination
- **Date:** 2026-08-10
- **Context:** Primary nav had been frozen at four pillars. Change detection produces a stream that is neither a finding (no policy asserts it is bad) nor an integration detail. A dashboard widget cannot carry window, significance, and class filters or old → new evidence.
- **Decision:** Add **Changes** (`/changes`) as a primary destination. This extends the four-pillar IA rather than reversing it; the removed inventory, graph, compliance, and access-review hubs stay removed.
- **Alternatives considered:** Dashboard widget only (too small); a tab under Findings (implies every change is a finding, which is the distinction the feature exists to make); an Integrations sub-page (buries an org-wide view under a per-connector hub).
- **Consequences:** Findings keeps its meaning as "a policy says this is wrong"; Changes answers "what moved". Each connector's first successful run is excluded as the baseline so the feed is not flooded on day one.

### DEC-020: Withdrawn
- Withdrawn before the first public release. The number is kept so later IDs stay stable.

### DEC-021: Explore as a primary nav destination
- **Date:** 2026-08-10
- **Context:** DEC-019 added Changes. The differentiation beat needs a focused "who can reach what, and how" surface without restoring report-hub sprawl.
- **Decision:** Add **Explore** (`/explore`) between Integrations and Changes: an identity-graph canvas on `@xyflow/react` + dagre with typed nodes, access-path edge styling, path highlight, and an inspect rail, not a path-list-only page.
- **Alternatives considered:** Path cards only; Findings-only deep links; restore the full report IA.
- **Consequences:** Primary nav is Dashboard · Integrations · Explore · Changes · Policies · Findings (+ Settings).
- **Status:** The nav list above is superseded by DEC-026, which added Identities.

### DEC-022: Custom connectors stay Python packages; generic HTTP is additive
- **Date:** 2026-08-21
- **Context:** A synthetic CRM app was used to prove out custom integration development. Operators need a Custom path in Integrations, and later apps should not each require a Dockerfile edit.
- **Decision:** Keep the Connector SDK (DEC-006) as the source of truth. Sequence: platform unlocks → reference Python connector for the synthetic app → Custom catalog → plugin-directory discovery → generic REST/OpenAPI connector. No in-app wheel upload: connectors remain trusted Python with no sandbox.
- **Alternatives considered:** No-code OpenAPI mapper only (weaker than the SDK story); wheel-upload API (unsafe without isolation).
- **Consequences:** Custom connectors are `ApplicationType.custom` / `ConnectorSource.CUSTOM`. Local live sync uses an explicit SSRF hostname allowlist, default-deny in production.
- **Status (0.4.0):** The synthetic-CRM reference connector and its posture pack were removed from the public tree; they depended on a synthetic CRM server that is not published. `examples/custom-connector` is the reference for custom connectors, and [`connectors/authoring-tutorial.md`](connectors/authoring-tutorial.md) builds one end to end.

### DEC-023: Dashboard builder: multi-board + constrained metric DSL
- **Date:** 2026-08-24
- **Context:** A personalizable catalog of posture widgets shipped first. Operators asked for named boards per application, custom metrics, chart visualizations, sized layouts, PDF export, and scheduled email.
- **Decision:** Evolve `/dashboard` into multi-dashboard org boards with a constrained metric DSL (allowlisted JSON over findings, connectors, policies, and changes; never arbitrary SQL). Built-in catalog widgets become DSL presets. The default Home remains the posture overview. PDF export and scheduled email share one SMTP `EmailTransport`. Boards stay under the Dashboard nav.
- **Alternatives considered:** Keep the catalog-only home (insufficient for admin and executive use); a new Reports primary nav (rejected by DEC-021); arbitrary SQL widgets (tenancy and injection risk).
- **Consequences:** Schedule recipients are org operators only; external recipients are not supported.
- **Status (0.4.0):** The `policy` and `change` DSL entities were removed. The DSL covers `finding`, `connector`, and `posture_trend`; see [`dashboards.md`](dashboards.md).

### DEC-024: Snapshot-diff is the source of truth for Changes
- **Date:** 2026-08-24
- **Context:** Operators want Changes search to be as easy as Findings and want every new integration to surface critical system changes. The tempting alternative is to stream provider audit logs so intra-day grants are never missed. Many SaaS apps have inventory APIs and weak or missing audit APIs; custom connectors would stall if logs were required; dual pipelines duplicate the same admin grant and disagree when logs are delayed.
- **Decision:** Changes is a black-box recorder. Every successful connector sync is a full inventory snapshot; `/changes` is the classified row-diff against the previous successful snapshot. Cadence is `schedule_cron` (twice daily is the recommended default). Provider audit logs (`activity_events`, `RESOURCE_TYPE=event`) remain optional findings detections for who/when and for intra-interval actions a snapshot diff cannot see; they must never be required to populate Changes. Intra-sync grant+revoke is an accepted miss and is stated in the UI. New connectors guarantee coverage by normalizing into the kinds the upsert already diffs (`grant`, `group_membership`, `oauth_*`, `setting`, `identity`) plus classifier signals, enforced by `kestrel connector validate` t0 → t1 fixtures. Graph edges without a `grant` row are not coverage.
- **Alternatives considered:** Stream audit logs into the Changes table (SIEM-shaped, blocks apps without logs, duplicates diffs); two feeds, logs when available and snapshots otherwise (operators cannot tell which is the source of truth); persisting classification on `events` as a blocker for search (deferred).
- **Consequences:** Search and noise suppression stay on the existing `events` feed. Connector authors get a coverage contract instead of a per-app change detector. An optional overlay may later attach audit actor and time onto an existing change row (it has since shipped; see [`changes.md`](changes.md)).


### DEC-025: Four connectors, covered against published baselines
- **Date:** 2026-09-15
- **Context:** Kestrel shipped five first-party connectors. Microsoft 365 was the
  shallowest by every measure — 11 object types, 3 policies, one declared change
  class, no activity collection, and it was never part of the demo estate.
  Meanwhile the four connectors that carry the product are uneven: Google
  Workspace has 14 object types and 15 policies against a CISA SCuBA baseline
  that enumerates over a hundred controls, and it is the only connector with no
  row in the connector bar and no posture-baseline matrix.
  Commercial SSPM vendors compete on application count — one advertises 200+ —
  while depth per application varies widely and is unverifiable from outside,
  because none of them publishes an enumerable list of the checks it runs.
- **Decision:** Kestrel supports **four** first-party applications — GitHub,
  Okta, Slack, and Google Workspace — and covers each against a *named, published,
  enumerable* baseline, publishing the coverage matrix. The Microsoft 365 / Entra
  connector and its `entra-posture` pack are removed from the tree. Breadth is not a
  goal; the Connector SDK remains the answer for any other application.
- **Alternatives considered:** Keep Microsoft 365 shallow and claim five
  connectors (dilutes the only differentiator that is defensible); keep it and invest to bring it to the same bar (a fifth
  deep connector costs more than deepening the four that already exist); move it
  to `examples/` as unsupported (leaves a connector nobody maintains implying
  first-party support).
- **Consequences:** The planned Microsoft Entra connector is dropped.
  `ApplicationType.MICROSOFT_365` and
  `ResourceType.SHAREPOINT_SITE` stay defined: PostgreSQL cannot remove a value
  from an enum type, and rows written by an earlier version must keep resolving.
  The UI keeps its Microsoft product mark, which serves OAuth applications
  discovered through the remaining connectors. Coverage claims must be backed by
  a matrix under `docs/posture-baselines/`; an unbacked depth claim is the same
  unverifiable assertion the vendors make.

### DEC-026: Identities as a primary nav destination
- **Date:** 2026-09-04
- **Context:** `/identities` and `/identities/[id]` shipped alongside the four
  first-party integrations, and became the page that answers "who is
  this person across every connected application" — the correlated account
  cluster, the roles each account holds, and the cross-application findings
  against it. It went into the primary navigation without a decision record, so
  DEC-021's consequence line ("Dashboard · Integrations · Explore · Changes ·
  Policies · Findings") kept describing a navigation that no longer shipped, and
  `docs/product.md`, `docs/architecture.md`, and the README drifted apart from
  `docs/roadmap.md` on what the product surface even is.
- **Decision:** **Identities** (`/identities`) is a primary nav destination,
  between Integrations and Explore. Explore stays the graph canvas for "who can
  reach what, and how"; Identities is the per-person view that Explore links
  into, and the two are not merged.
- **Alternatives considered:** Fold it into Explore (loses the list view an
  operator starts from, and makes the canvas carry two jobs); reach it only from
  finding evidence (the page is a destination in its own right during an
  investigation); drop it from the nav and leave the routes reachable by link
  (nav that hides a shipped surface is the drift this record exists to end).
- **Consequences:** Supersedes the nav list in DEC-021. Primary nav is
  Dashboard · Integrations · Identities · Explore · Changes · Policies ·
  Findings (+ Settings), and that list is what `docs/product.md`,
  `docs/architecture.md`, `docs/roadmap.md`, and `README.md` all state.

### DEC-027: Withdrawn
- Withdrawn before the first public release. The number is kept so later IDs stay stable.

### DEC-028: TOTP as the second factor, required per organization
- **Date:** 2026-10-07
- **Context:** Operators signed in with email and password only, in a product
  that holds administrative credentials for an organization's SaaS estate. A
  phished or reused password was a full compromise.
- **Decision:** Time-based one-time passwords (RFC 6238), implemented with the
  standard library and pinned to the RFC's test vectors; the secret is encrypted
  with the org key and a code cannot be replayed. Any operator can enrol; an
  admin can require it for the whole organization, in which case an operator
  without it must enrol straight after their next password sign-in. Recovery is
  ten single-use codes, plus an admin reset and `kestrel operator reset-mfa`.
  API tokens are exempt (they serve automation) but an operator with MFA can
  only mint one from a session that passed it.
- **Alternatives considered:** WebAuthn/passkeys (phishing-resistant, but needs
  a browser ceremony, attestation choices, and an RP ID tied to the
  deployment's domain; a strong follow-up rather than the first factor to ship);
  SMS or email codes (SIM-swap and mailbox compromise, and email requires SMTP);
  delegating to an IdP with OIDC (the right answer for larger deployments and
  planned separately, but a self-hosted tool must work without one).
- **Consequences:** Sessions carry an MFA state (`verified`, `challenge`,
  `enroll`); every route except the sign-in and enrolment routes accepts only
  verified sessions and API tokens. Requiring MFA signs nobody out; it takes
  effect at each operator's next sign-in. The session and token model it
  extends is [ADR-0008](adr/0008-opaque-tokens-for-operator-auth.md).
