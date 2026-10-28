# Identity graph and Explore

Who can reach what, across applications, and how: directly, through a group
or an inherited role, or through an OAuth grant. The graph is stored in
PostgreSQL ([ADR-0003](adr/0003-graph-representation-in-postgres.md)); do not
introduce a graph database without an accepted decision. **Explore**
(`/explore`) is the surface on top of it (DEC-021).

## Model

The graph is a derived read model. `kestrel.graph.writer` rebuilds
`graph_nodes` and `graph_edges` from the normalized entity tables on every
sync; the entity tables stay the source of truth.

| Nodes | Edges | `access_path` |
|-------|-------|---------------|
| `identity`, `application`, `group`, `role`, `permission`, `resource`, `oauth_application` | `member_of`, `assigned_role`, `grants_permission`, `has_permission`, `can_access`, `applies_to`, `possesses_scope`, `supported_by`, `maps_to` | `direct`, `inherited_group`, `inherited_role`, `oauth_derived`, `federated` |

Every node carries `application_type` and the application instance's display
name in `properties`, so two "Admin" roles from different tenants stay
distinguishable. Edges carry `properties` (`permission_level`,
`membership_role`, and for `possesses_scope` the scope names with their
sensitivity), `first_seen_at` / `last_seen_at`, and the connector run that
first observed them. `Grant.identity_id` is nullable: a team-level grant is
one edge, and per-member access is derived by traversal rather than
materialized.

## Queries

`kestrel/src/kestrel/graph/queries.py` answers reachability with a recursive
CTE: org-scoped, maximum depth 6, cycle detection via a path array, direction
`out` (what can this node reach), `in` (who can reach this node), or `both`.
`search_nodes` is an org-scoped label search for the picker.
`kestrel.graph.explore` layers multi-start traversal and identity collapse on
top; `kestrel.graph.context` and `edge_context` produce the plain-language
explanation for a node or an edge.

| Route | Purpose |
|-------|---------|
| `GET /graph/resolve` | Entity id + type → graph node |
| `GET /graph/search?q=` | Multi-type label search with `collapse=true` for identities |
| `GET /graph/nodes/{id}/neighbors` | Neighbors with `direction`, `depth`, `node_types`, `access_paths` filters and soft `max_nodes` truncation |
| `GET /graph/nodes/{id}/paths` | Grouped access paths with typed hops and a reach summary |
| `GET /graph/nodes/{id}/context` | Key properties, correlated accounts, neighbor and finding counts |
| `GET /graph/edges/{id}` | Edge explanation, endpoints, permission and membership details, provenance |
| `GET /identities`, `GET /identities/{id}`, `GET /identities/{id}/access`, `GET /identities/correlated` | Identity list (with `collapse`), detail with app context, groups, enriched grants, OAuth grants, findings, risk factors; correlated-account pairs |

Neighbors and paths bound the work, not just the response. The BFS runs one
frontier at a time, with one `IN` query per depth level, and each level fetches
a limited number of edges. It stops after visiting
`max(100, 4 × max_nodes)` nodes (or `4 × limit` for paths); the headroom is
for the type and access-path filters applied after the walk. When the cap
stops the walk, the response sets `truncated: true` and the paths `total` is
a lower bound. Nodes are kept nearest-first, so a truncated view of a hub
group still shows its closest neighbors.

## Cross-connector identity correlation

![An identity correlated across four applications, with its accounts, access, groups, and open findings](images/identity-detail.png)

Identities are stored per application instance; the rows are never merged.
Correlation is a read-model overlay applied in Explore and in policy data
loading:

| Confidence | Rule |
|------------|------|
| High | Same normalized email |
| Medium | A multi-token display name that is unique within each application instance (`Grace Hopper` merges; `Alex` or the login `alice` does not) |
| Live GitHub | Email or name only when the API or fixture provides them; no invented noreply addresses |

The representative account for search prefers an IdP account (Okta,
Google Workspace). Neighbors and paths start a BFS from every correlated
account and rewrite sibling identity nodes onto the focused node, so one
person shows their access across all synced tenants from a single focus. The
inspector lists the underlying `accounts[]` (application, email, MFA,
disabled). Identity rows for policy evaluation carry
`privileged_application_types` derived by the same email rule, and a
`cluster` block built from `identity_links`: every account with its state,
worker type, roles and trusted activity, the identity-provider status, the
person's resolved `worker_type` and latest activity, and the representative
account ([`policies.md`](policies.md#resource-types-worth-knowing)).

## Explore canvas

![Explore focused on one person across four applications, with the inspector's access paths](images/identity-access-graph.png)

Built on `@xyflow/react` + dagre: typed node silhouettes, hierarchical layout,
MiniMap and controls, a legend, an inspect rail, and URL-driven state so a
view is shareable.

| Parameter | Meaning |
|-----------|---------|
| `focus`, `focus_type` | Entity to center on (default type `identity`) |
| `depth` | 1–6 (default 3) |
| `search` | Label or email query; one match auto-focuses, many open a picker |
| `direction` | `out` (default), `in`, `both` |
| `node_types`, `access_paths` | Comma-separated filters, mirrored as toolbar chips |
| `labels` | `compact` (default), `hover`, `off` |

Readability follows three layers so the canvas does not turn into a wall of
text: line color and dash encode **how** (`access_path`: solid `direct`,
distinct strokes for `inherited_group` and `inherited_role`, dashed
`oauth_derived`); a short verb or permission chip encodes **what**
(`member of`, `assigned`, `can access`, or the `permission_level` when set;
OAuth edges show the first sensitive scope); hover and the inspector give the
full sentence and the hop story. Role nodes show a `Privileged` chip;
resource nodes show the incoming permission level.

Vendor marks identify applications at a glance: `application` and
`oauth_application` nodes carry the vendor mark inside the silhouette, other
node kinds carry a corner badge, correlated identities stack up to three
marks, and unknown or custom applications fall back to a letter mark.
`apps/web/src/lib/app-mark.ts` resolves the mark from OAuth display names,
then `properties.application_type`; first-party SVG paths are bundled with
no vendor CDN fetches (`brand/THIRD_PARTY_MARKS.md`). The MiniMap stays
silhouette-only and the pack marketplace stays letter-mark only.

Explore works against the demo data with no hand SQL: focus the promoted
GitHub admin or an Okta admin and follow the outbound path into a sensitive
repository or Slack workspace; flip to inbound on that resource to see every
holder, including an OAuth grant path; focus the Okta `engineering` group with
direction `both` to see members on one side and the apps it grants on the
other.

## Risk factors on identities

Identity detail lists explainable, labeled risk factors, never a composite
score. One of them is **peer privilege**: an identity holding strictly more
privileged-role assignments than the median of its peers, where peers share a
graph `member_of` group (never an inferred job title), the median counts
zeros, and groups need at least three members to count. When an identity is
in several qualifying groups the largest excess is reported. Others include
cross-application privileged concentration (privileged roles in two or more
application types under one correlated identity), MFA state, external or
disabled status, and dormancy.

## What is proposed

A canonical person table with confidence-scored links, explicit confidence
scores on edges, richer edge history, and graph-database storage are all
proposed only and would require a new accepted decision. Groups, roles, and
resources are not collapsed across applications.
