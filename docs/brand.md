# Naming and identifiers

The product, the project, and the technical identifiers that carry the name.
Visual identity (logos, icons, tokens, UI style) lives in
[`../brand/`](../brand/).

## Names

| Context | Name |
|---------|------|
| Product, UI, CLI, documentation | **Kestrel** |
| Project and repository | **Kestrel**, a personal open-source project ([`kestrel-security/kestrel`](https://github.com/kestrel-security/kestrel)) |
| Tagline | Open-source security for SaaS. |

## Technical identifiers

These are contracts. Changing one is a breaking change for operators, so it
needs a migration note in `CHANGELOG.md`.

| Surface | Value |
|---------|-------|
| CLI | `kestrel` |
| Python packages | `kestrel`, `kestrel_api`, `kestrel_worker`, `kestrel_connector_*` |
| Environment variables | `KESTREL_*` |
| Connector entry-point group | `kestrel.connectors` |
| Ticket-provider entry-point group | `kestrel.ticket_providers` |
| Webhook headers | `X-Kestrel-Signature`, `X-Kestrel-Timestamp` |
| Session cookie | `kestrel_session` |
| Prometheus metrics prefix | `kestrel_` |
| Secrets HKDF info string | `kestrel-connector-secret` |
| GitOps manifest `apiVersion` | `kestrel.dev/v1` |

## Runtime brand assets

The web app ships copies of the brand assets; regenerate them from `brand/`
rather than editing them in place:

- `apps/web/public/brand/kestrel-logo-horizontal-{dark,light}.svg`: primary chrome lockup
- `apps/web/public/brand/kestrel-app-icon-{dark,light}.{svg,png}`: install and touch icons
- `apps/web/public/brand/kestrel-open-graph-dark.png`: link preview card
- `apps/web/public/favicon.{svg,ico}` and `site.webmanifest`
- Tokens mapped into `apps/web/src/app/globals.css` (dark-first)

Third-party product marks shown in Explore and finding investigation are
covered in [`../brand/THIRD_PARTY_MARKS.md`](../brand/THIRD_PARTY_MARKS.md).
