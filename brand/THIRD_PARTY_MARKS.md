# Third-party product marks in the UI

Kestrel’s Explore graph and finding investigation surfaces show small product
marks (GitHub, Slack, Okta, Google Workspace, Microsoft 365) so operators can
scan which SaaS an identity can reach.

Microsoft 365 is on that list although Kestrel has no Microsoft connector
(DEC-025). The mark is resolved from an OAuth application’s display name, so a
Microsoft application authorized by a person and discovered **through** Okta or
Slack still renders with its own mark rather than an unhelpful letter tile.

## Trademark

These marks identify third-party products and remain the trademarks of their
respective owners. Use in Kestrel does **not** imply endorsement, sponsorship,
or affiliation.

## Copyright of SVG artwork

Simplified SVG paths under `apps/web/src/components/brand/app-mark.tsx` are
first-party copies derived from the [Simple Icons](https://simpleicons.org/)
project (Creative Commons Zero / public domain). Kestrel does **not** depend on
the `simple-icons` npm package at runtime and does not fetch logos from vendor
CDNs.

## Policy

- **Explore / findings graph:** vendor marks allowed (this document).
- **Policy pack marketplace:** letter-mark tiles only — see
  `docs/policies.md`.
- Do not recolor Kestrel brand marks to imitate vendors.
- Unknown / `custom` application types use a letter-mark fallback.
