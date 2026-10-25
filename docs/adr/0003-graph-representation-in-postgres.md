# ADR-0003: Graph Representation in PostgreSQL

## Status

Accepted

## Context

Kestrel needs to answer graph-shaped questions — "who has access to this application," "what can this identity access across every connected application, including group/role-inherited access," "what access would remain if an IdP account were disabled" — over identity, group, role, permission, resource, and OAuth-application relationships. The product spec explicitly directs against introducing Neo4j or another graph database until there's a demonstrated requirement, and prefers PostgreSQL with normalized node/edge tables.

## Decision

- **`graph_nodes`**: one row per graph-participating entity (`node_type` enum: `identity`, `application`, `group`, `role`, `permission`, `resource`, `oauth_application`; `object_id` pointing at that entity's own primary key in its normalized table; `label` for display; `properties` JSONB for small denormalized attributes needed by the graph UI without extra joins, e.g. `{"mfa_enabled": false}`). Unique on `(org_id, node_type, object_id)`.
- **`graph_edges`**: a single polymorphic table, not one table per edge type. `edge_type` enum (`member_of`, `assigned_role`, `grants_permission`, `has_permission`, `can_access`, `applies_to`, `possesses_scope`, `supported_by`, `maps_to`); `access_path` enum (`direct`, `inherited_group`, `inherited_role`, `oauth_derived`, `federated`) distinguishing *how* access was reached; provenance (`source_connector_run_id`, `first_seen_at`, `last_seen_at`); `properties` JSONB for edge-specific extras (e.g. `permission_level`). Indexed on `(org_id, source_node_id, edge_type)` and `(org_id, target_node_id, edge_type)`.
- **Not EAV.** Every field every edge/node needs (org scoping, timestamps, provenance) is a typed column; JSONB is reserved for genuinely variable, edge-type-specific extras. This keeps the two hot indexes simple and avoids the query-explosion problems generic EAV schemas produce at scale.
- **Traversal via recursive CTEs** (`WITH RECURSIVE`), not the ORM query builder — see `kestrel/graph/queries.py`. Bounded to a `MAX_TRAVERSAL_DEPTH` (6 hops) with a `path` array column to detect and stop at cycles.
- **`graph_nodes`/`graph_edges` are a derived read-model, not a source of truth.** They're rebuilt (upserted) by `kestrel/graph/writer.py` from the normalized entity tables (`identities`, `groups`, `roles`, `resources`, ...) during every sync. If the normalized schema evolves, the graph projection can be rebuilt from it; it's never hand-edited or treated as the authoritative record.

## Why

- The spec explicitly forbids introducing a dedicated graph database at this stage, and the actual traversal depth needed (Identity → Group → Role → Permission → Resource) is shallow — rarely more than 4–5 hops — so recursive CTEs perform adequately at the scale a single connected org produces (tens of thousands of nodes/edges, not millions).
- Staying in PostgreSQL avoids a second datastore with its own backup story, consistency model, and operational surface — a meaningful simplicity win for an OSS product meant to be self-hosted by teams without a dedicated graph-database operator.
- `access_path` as a first-class column (not buried in JSONB) is what lets the UI and the legacy policy DSL policies cheaply distinguish "this identity has direct admin access" from "this identity inherited access through a group" — a distinction the product principles call out explicitly (`docs/adr` reference: "Clearly distinguish direct, inherited, federated, and OAuth-derived access").

## Consequences

- A known limitation, documented in `kestrel/graph/writer.py`: relationship `source_ref`/`target_ref` resolution (from a connector's provider ids to graph node ids) is flattened across entity kinds within one collection run. This works because GitHub's (and most SaaS APIs') object ids are globally unique across object types; a connector whose kinds share an id space would need namespaced refs instead. Flagged for connector authors in `docs/connectors/authoring-tutorial.md`.
- If org size or traversal depth grow enough that recursive CTEs become a bottleneck, the escape hatch is a materialized closure table (precomputed reachability) rather than switching datastores — revisit only with a demonstrated need, per the spec's own guidance.
