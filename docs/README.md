# Kestrel documentation

Every page under `docs/` is listed here; `scripts/docs-check.sh` fails when
one is not. Start with [`getting-started.md`](getting-started.md).

These pages are published at [docs.kestrelsecurity.io](https://docs.kestrelsecurity.io/)
for each release. A new page also goes in `mkdocs.yml`'s `nav`; preview the site
with `make docs-serve`.

References like `DEC-024` throughout these pages are entries in the decision log,
[`decisions.md`](decisions.md); `ADR-0004` and similar are the full records under
[`adr/`](adr/).

## Start here

| Page | What it covers |
|------|----------------|
| [`getting-started.md`](getting-started.md) | Prerequisites, first run, ports, configuration, operators and tokens, everyday commands, troubleshooting |
| [`faq.md`](faq.md) | Telemetry, permissions, data storage, platforms, production readiness, naming, adding an application, reporting a vulnerability |
| [`demo.md`](demo.md) | What `kestrel demo` generates, the drift timeline, and a walkthrough script |
| [`architecture.md`](architecture.md) | Components, the sync pipeline, data model, extension model, proposed target |
| [`threat-model.md`](threat-model.md) | Assets, trust boundaries, what Kestrel protects against and what it does not yet |
| [`testing.md`](testing.md) | The six rules, tiers, harness, commands, review checklist |

## Features

| Page | What it covers |
|------|----------------|
| [`connectors.md`](connectors.md) | First-party connectors, lifecycle, SDK and manifest contract, instances and secrets, custom connectors, live smoke checklist |
| [`policies.md`](policies.md) | Policy contract, runtime, evaluation, workbench, AI drafts, packs, coverage, marketplace |
| [`policies-for-agents.md`](policies-for-agents.md) | Writing policies with an outside AI agent: the authoring contract and the checks to run |
| [`posture-baselines/README.md`](posture-baselines/README.md) | Control-mapping matrices per application: baseline control, profile, required data, collection status, implementing policy |
| [`posture-baselines/github.md`](posture-baselines/github.md), [`okta.md`](posture-baselines/okta.md), [`slack.md`](posture-baselines/slack.md), [`google-workspace.md`](posture-baselines/google-workspace.md) | The per-application matrices (CIS GitHub Benchmark v1.2.0; DISA Okta IDaaS STIG; NIST CSF 1.1 / CIS Controls v8.1 for Slack; CISA SCuBA for Google Workspace) |
| [`findings.md`](findings.md) | Lifecycle, search, detail surfaces, handoff and tickets, personal notifications, verification, toxic combinations |
| [`changes.md`](changes.md) | Snapshot-diff change feed, change classes, search, what it cannot see, coverage contract |
| [`identity-graph.md`](identity-graph.md) | Graph model and queries, cross-connector correlation, the Explore canvas, risk factors |
| [`dashboards.md`](dashboards.md) | Boards, built-in widgets, the metric DSL, posture trend, export and schedules |
| [`ticketing.md`](ticketing.md) | GitHub Issues and Jira Cloud providers, Settings and finding UI, extending |
| [`gitops.md`](gitops.md) | `kestrel export` / `plan` / `apply` and the desired-state manifest |
| [`domain-model.md`](domain-model.md) | Every model, grouped, including tables that have no surface yet |
| [`user-experience-principles.md`](user-experience-principles.md) | The product surface and the UX rules it follows |

## Connectors

| Page | What it covers |
|------|----------------|
| [`connectors/authoring-tutorial.md`](connectors/authoring-tutorial.md) | Build a connector end to end with the scaffold |
| [`connectors/github-setup.md`](connectors/github-setup.md) | Classic PAT or GitHub App |
| [`connectors/google-workspace-setup.md`](connectors/google-workspace-setup.md) | Service account with domain-wide delegation |
| [`connectors/okta-setup.md`](connectors/okta-setup.md) | SSWS API token; building a test tenant |
| [`connectors/slack-setup.md`](connectors/slack-setup.md) | User OAuth token, Enterprise Grid scopes; building a test tenant |

## API and operations

| Page | What it covers |
|------|----------------|
| [`api.md`](api.md) | Authentication, errors, pagination, rate limits, webhooks, and generated route tables |
| [`api-guidelines.md`](api-guidelines.md) | Conventions every route follows |
| [`deployment.md`](deployment.md) | Running Kestrel with Docker Compose (`deployments/compose/`), behind a reverse proxy, upgrades, backups; building the images |
| [`observability.md`](observability.md) | Prometheus metrics, structured logs, optional OTLP tracing |
| [`operations/scheduled-syncs.md`](operations/scheduled-syncs.md) | `schedule_cron` and the beat dispatcher |
| [`operations/rate-limiting.md`](operations/rate-limiting.md) | Tiers, backends, tuning |
| [`operations/data-retention.md`](operations/data-retention.md) | Trimming `raw_source` and other retention choices |
| [`operations/release-process.md`](operations/release-process.md) | Versioning, how a release is cut, and what a release tag runs |

## Project

| Page | What it covers |
|------|----------------|
| [`product.md`](product.md) | Product definition and long-term vision |
| [`roadmap.md`](roadmap.md) | Capability status and what is planned next |
| [`decisions.md`](decisions.md) | Decision log; accepted architecture decisions have full records under [`adr/`](adr/) |
| [`images/README.md`](images/README.md) | How the README screenshots are captured and kept current |
| [`brand.md`](brand.md) | Names and technical identifiers (visual identity lives in [`../brand/`](../brand/)) |
| [`templates/decision-record.md`](templates/decision-record.md) | Decision-record template |

Root documents: [`../README.md`](../README.md), [`../CONTRIBUTING.md`](../CONTRIBUTING.md),
[`../SECURITY.md`](../SECURITY.md), [`../SUPPORT.md`](../SUPPORT.md),
[`../GOVERNANCE.md`](../GOVERNANCE.md), [`../MAINTAINERS.md`](../MAINTAINERS.md),
[`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md), [`../CHANGELOG.md`](../CHANGELOG.md).
