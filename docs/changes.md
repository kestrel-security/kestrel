# Changes

**Changes** answers "what moved" across every connected application. Every
successful connector sync is a full inventory snapshot; the feed is the
classified diff against the previous successful snapshot (DEC-024). A finding
means a policy says something is wrong; a change means something moved,
whether or not a policy cares.

## How it works

1. The sync upsert (`kestrel.sync.upsert`) writes an `events` row for every created, updated, or deleted entity and relationship: identities, grants, group memberships, OAuth applications, scopes and grants, and tenant settings. Provider audit-log rows are upserted like any other entity but never write an `events` row (`NON_FEED_KINDS`): the feed applies its scan cap in SQL before classification, so a chatty audit log would otherwise push real drift out of the window.
2. `kestrel.changes.classify` derives a **change class** and a **significance** for each event at read time from the entity kind, the field that moved, and classifier signals the connector set (`Role.is_privileged`, `permission_level`, `OAuthScope.is_sensitive`, `TenantSetting.category`, `mfa_enabled`). Classification is not persisted on `events`.
3. `GET /changes` returns the ranked feed with `before` / `after` evidence, and `/changes` renders it.
4. `kestrel.graph.snapshots` records a hashed snapshot of the graph per run as evidence that the diff is against a complete inventory; it is not the query path.

Each connector instance's first completed full run is the **baseline** and is
excluded from the feed, so onboarding an application does not produce a day of
"new admin" rows. `partial_failure` runs qualify: a connector that can never
read one family (a GitHub org without audit-log access) is partial on every
run and would otherwise have no baseline at all. Failed runs and events-only
polls never qualify. Volatile telemetry (`last_active_at`, last-login and
API-token timestamps) updates the entity but does not write `events` rows.

## Change classes

| Class | Significance | Emitted when |
|-------|--------------|--------------|
| `admin_granted` / `admin_revoked` | high | A grant to a privileged role, or a grant with `permission_level=admin`, appears or disappears |
| `privilege_escalated` / `privilege_reduced` | high / medium | A grant's `permission_level` moves up or down a rankable scale (`read` → `write` → `admin`) |
| `access_granted` / `access_revoked` | medium | A non-privileged grant appears or disappears |
| `group_member_added` / `group_member_removed` | medium | A group membership changes |
| `oauth_app_installed` / `oauth_app_revoked` | high / medium | An OAuth application grant appears or disappears |
| `oauth_scope_expanded` | high | An existing OAuth grant gains a sensitive scope |
| `external_sharing_enabled` | high | A `category=sharing` setting moves to a permissive value |
| `mfa_disabled` | high / medium | An identity's `mfa_enabled` flips from true to false (high when the identity holds a privileged role). A flip to unknown (`null`) is lost visibility, such as a token that can no longer read 2FA status, and is classed `other` |
| `identity_added` / `identity_removed` / `identity_disabled` | low / medium | Identity lifecycle |
| `config_drift` | medium | A `security`, `sharing`, or `access` setting changes |
| `other` | low | Any other diff |

The authoritative list is `GET /changes/classes` and the `ChangeClass` enum in
`kestrel/src/kestrel/changes/classify.py`.

## Searching the feed

`GET /changes` accepts a window (`since` / `until`), `significance`,
`change_class`, `connector_instance_id`, and a `search` string. Search is
identity-aware: the string is resolved against identities, groups, resources,
and applications first, and events for those entities (and grants or
memberships pointing at them) are loaded directly through a subquery, never a
materialized ID list, so a broad term in a large tenant cannot overflow the
driver's bind-parameter limit, so a high-significance
grant is not hidden behind a scan cap by a flood of low rows. Tokens follow
the Findings grammar (`class:admin_granted`, `significance:high`, `app:okta`,
`person:grace@example.com`) alongside free text over label, summary, email,
display name, before/after values, and application name. Filters are URL
parameters, so a view is shareable.

The default view shows medium significance and up, with high rows pinned;
`significance:low` or `class:other` opens the rest. The before/after cell
follows `change_type`: a `created` row reads `+ Admin`, a `deleted` row
`− Admin`, and only an `updated` row uses the `before → after` arrow, so a
grant never looks like a removal and the `+`/`−` glyph carries direction
without relying on color. Screen readers get "added Admin" / "removed Admin".
When neither side was recorded the cell says so instead of showing a dash. An
expanded row shows a Before | After panel with field-level detail. `null`
remains the wire representation of "this side did not exist"; the shape is
chosen in `apps/web/src/lib/change-delta.ts`.

## What Changes cannot see

Kestrel records the tenant at each successful sync. An action granted and
fully reversed between two syncs does not appear. The UI says so. Cadence is
the operator's `schedule_cron` on each connector instance; twice daily is a
sensible default and hourly is available where the provider's API allows.

Provider audit logs are a separate thing: collected as `activity_events`
where a connector supports them, evaluated by `RESOURCE_TYPE=event` policies,
and surfaced as findings for the who/when that a snapshot diff cannot carry.
They are never required to populate Changes, so connectors for applications
with no audit API still get full change coverage.

Where a connector does collect an audit log, the feed overlays the actor onto
the row it already has (`kestrel.changes.overlay`): `actor_email`,
`actor_provider_id`, `actor_action`, and `actor_occurred_at`. The overlay is
additive in the strict sense. It never adds, removes, or reclassifies a row,
so a connector with no audit log produces exactly the feed it produced before.
Matching is deliberately narrow, because a wrong actor is worse than no actor:
the audit row must come from the same application instance, its target must
resolve to the change's subject (grants, memberships, and OAuth grants resolve
through to their identity), its normalized action must be one that could have
caused that change class, and it must have occurred inside the diff interval,
the previous full run's start to this run's start. Which actions can attribute
which classes is `_ACTIONS_FOR_CLASS` in the overlay module, keyed on the
normalized action, so widening a connector's curated taxonomy widens
attribution without any feed change.

## Guaranteeing coverage in a new connector

Coverage is a property of what a connector normalizes, not of a per-app
change detector. A connector that emits `grant` rows with `is_privileged`
roles, `oauth_*` rows with sensitive-scope flags, `setting` rows with
categories, and `identity` rows with `mfa_enabled` populated gets every class
above for free. `kestrel connector validate` replays the connector's
`fixtures/` (t0) and `fixtures/changed/` (t1) and fails if a class the
manifest declares in `change_classes` does not appear in the diff. Graph
edges alone are not coverage; the GitHub org-admin class was invisible until
the connector emitted a grant row. Details: [`connectors.md`](connectors.md#change-coverage-contract).

## Demo

`kestrel demo change` replays a back-dated drift timeline that exercises every
change class: see [`demo.md`](demo.md).
