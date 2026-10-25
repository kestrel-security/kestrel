# Product definition and vision

What Kestrel is for, who it serves, and where it is going. Near-term
sequencing and open work are in [`roadmap.md`](roadmap.md); new bugs and
feature requests go in [GitHub issues](https://github.com/kestrel-security/kestrel/issues).

## Who it is for

Security engineers, SaaS security teams, identity engineers, detection
engineers, security operations, governance/risk/compliance teams, IT
administrators, and platform engineers building internal integrations.

## The problems

1. Connecting custom or niche SaaS apps depends on vendor roadmaps.
2. Policies are hard to write, test, and review in git.
3. Cross-application access paths are invisible.
4. Alerts lack evidence and remediation clarity.
5. Closed SSPM tools are opaque and difficult to self-host.
6. Compliance mapping is disconnected from real detections.

## Core workflows

1. **Onboard** an application (Integrations: connector instance with encrypted secrets, or fixtures).
2. **Inventory** apps, identities, groups, roles, resources, and settings.
3. **Author or install** Python policies and packs (Policies hub and git).
4. **Triage findings** with search-first UX, evidence, ownership, and playbooks.
5. **Watch what changed** in the classified change feed.
6. **Operate from home** via personalizable dashboards.
7. **Remediate** with status, exceptions, playbooks, and tickets today; guided or automated remediation with approvals later.
8. **Extend** via the Connector SDK and packs without forking core.

**Product surface:** Dashboard · Integrations · Identities · Explore · Changes ·
Policies · Findings (+ Settings) (DEC-019, DEC-021, DEC-026). Identity detail,
connector health and run history, the pack catalog, and personal notifications
(the sidebar bell) are reached from those pages rather than from the primary
nav.

**Usability bar:** a security engineer should onboard an app, author a policy,
investigate a finding, and validate remediation without becoming an expert in
Kestrel internals.

## Principles

1. Prefer readable systems over clever ones.
2. Evidence and provenance on every security claim.
3. Policies and connectors are code: versioned and testable.
4. Smallest useful self-hosted deployment first.
5. One complete product. The Connector SDK and policy engine are never stubs or gated (DEC-009).
6. Secure defaults; fail closed on authorization.
7. AI assists; it does not silently decide risk.

## Non-goals (current horizon)

- Replacing a full SIEM or SOAR.
- Endpoint or cloud CSPM as primary scope.
- Mandating a vendor-hosted control plane.
- Auto-remediation without human-configurable approvals.
- A graph database mandate.
- Rebuilding any existing SSPM feature-for-feature.

## Success signals

| Signal | What it looks like |
|--------|--------------------|
| Time to first finding | `kestrel demo up` → findings in the UI in minutes, no cloud credentials |
| Connector author success | A new connector validates on fixtures without core changes |
| Policy author success | A policy validates and fixture-tests without reading evaluator internals |
| Finding trust | Every finding shows evidence and remediation text |
| Live time-to-value | Live Okta or Google Workspace → first IdP finding without the CLI |
| Operational safety | Auth required; secrets never returned in plaintext |
| Contributor health | External connector and policy PRs are reviewable via `CONTRIBUTING.md` |

## Long-term vision

Kestrel aims to become the security control plane for SaaS applications,
identities, permissions, configurations, data exposure, and security
operations. This section is intentionally ambitious and is not the roadmap.

Security teams should be able to answer, continuously and with evidence:

1. What SaaS applications and third-party OAuth apps exist in our environment?
2. Who (human or non-human) can access what, across applications, and how?
3. Which configurations and grants violate our policies?
4. What should we fix first, and how do we prove we fixed it?

| Capability | Intent |
|------------|--------|
| SaaS application inventory | Authoritative catalog of connected applications and the OAuth apps they expose |
| OAuth application discovery | First-class visibility into OAuth apps, scopes, and grants |
| Native and custom connectors | First-party connectors plus an SDK for internal apps |
| Identity and entitlement graph | Cross-app correlation of humans, services, groups, roles, permissions |
| Cross-application access analysis | "What remains if this IdP account is disabled?" |
| Configuration posture management | Continuous drift detection, mapped to published benchmarks |
| Policy-as-code | Git-versioned Python policies and packs; optional SQL detections later |
| Custom compliance rules | Map detections to SOC 2, CIS, NIST, or custom frameworks |
| Continuous monitoring | Scheduled syncs, health, alerting |
| Risk prioritization | Explainable prioritization; never an unexplained score as the only signal |
| Investigation timelines | Reconstruct how access and configuration evolved |
| Guided and approved remediation | Step-by-step fix paths; automation behind explicit approval gates |
| Multi-organization management | Optional delegation when one deployment serves many teams |
| Plugin and integration ecosystem | Shared connectors, policies, ticketing, SIEM integrations |
| AI-assisted investigation and authoring | Optional assistants; never the sole authority for deterministic decisions |
| Deployment options | Docker Compose self-hosting from the shipped Dockerfiles; hardening and HA over time |

Principles that survive the long term: a complete self-hosted product;
deterministic security decisions (AI may draft, evaluation stays reviewable);
evidence over dashboards; extensibility without core forks; self-hostable by
default so operators never have to send posture data to anyone else.

Explicit non-promises: Kestrel will not require a proprietary rule black box
for core detections, will not withhold the connector SDK or policy language,
and will not adopt exotic infrastructure (graph databases, heavy workflow
meshes) without evidenced need and an accepted decision.
