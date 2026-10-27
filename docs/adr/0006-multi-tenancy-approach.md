# ADR-0006: Multi-Tenancy Approach

## Status

Accepted

## Context

Kestrel is a self-hosted product; multi-team / multi-organization delegation may come later. We need a tenancy model that fits single-org self-hosting today without making multi-org a schema migration later (DEC-009: one build, everything ships enabled).

## Decision

**Default deployment is one organization** — one self-hosted instance, one PostgreSQL database, one set of connectors, matching how most self-hosted security tools are actually run. `kestrel init` bootstraps exactly one `Organization` row; v1 authentication is local operators with fixed RBAC (see ADR-0008).

**However, every table still carries `org_id` and every query is scoped by it** — there is no code path in the data model, the sync pipeline, the policy evaluator, or the API that treats "single org" as a structural assumption baked into the schema. `apps/api/src/kestrel_api/deps.py`'s `get_current_org` dependency resolves the single `Organization` row today; every router filters by `org.id` exactly as it would if there were ten organizations in the database.

Row-level scoping is enforced in **application code** (the `get_current_org` FastAPI dependency, `WHERE org_id = ...` on every query), not PostgreSQL Row-Level Security (RLS) policies, for v1.

## Why

- Adding `org_id` everywhere costs almost nothing now and is expensive to retrofit later — every table, every query, every test fixture would need revisiting. Building it in from the first migration is the cheap time to pay this cost.
- Multi-team/multi-org delegation can be a genuinely additive layer later: RBAC scoping plus a UI org-switcher on top of a schema that already partitions everything by `org_id`, rather than a breaking schema migration.
- Skipping Postgres RLS for v1 is a deliberate, lower-stakes simplification: RLS adds real operational complexity (a second identity/policy system living inside Postgres, interacting with connection pooling in ways that need care) that isn't justified when there's exactly one org and the application layer already enforces scoping consistently. RLS is a reasonable hardening addition later, not a v1 requirement.

## Consequences

- A bug in a router that forgets to filter by `org_id` wouldn't be caught by a database-level constraint today (no RLS backstop) — code review and the test suite are the safety net. This is an explicit, documented tradeoff, not an oversight; revisit if/when multi-org makes RLS's operational cost worth paying.
- `kestrel init` is not idempotent-safe for creating a *second* organization — running it again against an already-initialized database returns the existing org rather than creating a new one, matching the "one org per deployment" model.
