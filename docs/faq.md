# Frequently asked questions

Short answers, with links to the page that has the detail.

## Does Kestrel phone home or collect telemetry?

No. Kestrel has no analytics, usage reporting, crash reporting, or update
check, and the web UI loads nothing from third-party hosts at runtime.

The outbound connections a running deployment makes are the ones you
configure: the SaaS APIs of the integrations you add, and optionally your SMTP
server, webhook endpoints, Jira Cloud or GitHub for ticketing, an LLM provider
for AI policy drafts, and an OTLP collector for traces. Every one of them is off
until you set it up.

Two build-time notes:

- Next.js sends anonymous telemetry from `next build` and `next dev` by
  default. The web image sets `NEXT_TELEMETRY_DISABLED=1`, so the Docker build
  does not. For a host-run `pnpm --filter kestrel-web dev`, export
  `NEXT_TELEMETRY_DISABLED=1` or run `pnpm --filter kestrel-web exec next
  telemetry disable` once.
- Building the web image downloads its two fonts from Google Fonts; the built
  image serves them itself, so browsers never contact Google
  ([`threat-model.md`](threat-model.md)).

## What permissions does it need? Will it change anything in my tenants?

Kestrel only reads. Connectors issue read requests, and there is no write-back
remediation. Each connector's `manifest.yaml` declares the scopes it needs, and
the connector loader refuses a manifest that declares a known write scope
(`kestrel/connectors/readonly_scopes.py`). Two caveats the setup guides spell
out: a few providers have no read-only form of a permission Kestrel needs (for
example GitHub's classic `repo` scope), and the loader cannot inspect the
credential you paste, so grant only what the guide lists.

The per-connector list of scopes, roles, and plan requirements is
[Permissions at a glance](connectors.md#permissions-at-a-glance).

## Where is my data stored, and how are secrets protected?

Everything is in your PostgreSQL database: the normalized inventory, the raw
provider payloads kept as provenance, findings, the change history, and the
audit log. Redis holds only the job queue. Nothing leaves your deployment
except through the connections listed above.

Stored secrets (integration credentials, webhook signing secrets, ticketing
tokens, LLM API keys, SMTP passwords, TOTP secrets) are encrypted with
AES-256-GCM under a per-organization key derived from `KESTREL_MASTER_KEY`, and
each ciphertext is bound to the row it belongs to
([ADR-0004](adr/0004-secrets-storage-and-encryption.md)). API responses never
return them. Back up the master key separately from the database: a backup
cannot be decrypted without it. The raw payloads can carry sensitive SaaS data;
[`operations/data-retention.md`](operations/data-retention.md) covers trimming
them.

## How is it different from a commercial SSPM or the vendors' admin consoles?

Each application's admin console shows that application. Kestrel's job is the
view across them: one person's accounts correlated across GitHub, Okta, Slack,
and Google Workspace, effective access through groups, roles, and OAuth grants,
and findings that need two applications to see, such as an account the
identity provider disabled that is still active elsewhere.

Commercial SaaS security posture management products cover the same problem
with many more integrations, a hosted service, vendor support, and often
remediation or SaaS discovery. Kestrel is self-hosted, Apache-2.0, four
first-party connectors plus an SDK for your own, read-only, and its detections
are Python files in git that you can read, test, and change. It does not
discover unsanctioned SaaS and does not write back to your tenants
([`roadmap.md`](roadmap.md)).

## What platforms does it run on?

Anywhere Docker with Compose v2 runs. The images build on the official
`python:3.12-slim` and `node:22-slim` images, and the stack uses `postgres:16`,
`redis:7-alpine`, and `caddy`; all of them publish `linux/amd64` and
`linux/arm64` variants, so the same `up --build` works on x86-64 Linux and on
Apple Silicon or other arm64 hosts. Allow about 4 GB of free memory for the
build. [Building the images](deployment.md#building-the-images) covers
cross-building for another architecture.

## Can I use it in production?

Kestrel is pre-1.0. The Docker Compose deployment is supported on a single
host, behind TLS and a network boundary you trust; there is no high-availability
setup, SSO for operators, or KMS integration yet, and live-tenant smoke
sign-off is still open for the first-party connectors
([`connectors.md`](connectors.md#the-connector-bar)). Read
[`threat-model.md`](threat-model.md) for what it does and does not defend
against, and [`deployment.md`](deployment.md) before exposing it to a network.
Only the latest release receives security fixes.

## Is this the Kestrel threat hunting language, or the `kestrel` package on PyPI?

No to both. This project is unrelated to the Kestrel threat hunting language
(`kestrel-core` / `kestrel-lang`), and it is not published on PyPI:
`pip install kestrel` installs a different project. Run Kestrel from Docker or
from a checkout of this repository.

## How do I add an application that is not supported?

Write a connector: a Python package with a manifest, a collector, and a
normalizer, testable offline with fixtures and no core changes.
[`connectors/authoring-tutorial.md`](connectors/authoring-tutorial.md) builds
one end to end, and `examples/custom-connector/` is a working example. Custom
connectors appear under Integrations next to the first-party ones
([Custom connectors](connectors.md#custom-connectors)).

## How do I report a vulnerability?

Privately, through GitHub private vulnerability reporting; do not open a public
issue. [`SECURITY.md`](../SECURITY.md) has the link, scope, and response times.
