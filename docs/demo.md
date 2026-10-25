# Demo data and walkthrough

`kestrel demo up` builds a synthetic but coherent estate so every page in the
product has something real behind it, with no cloud credentials. This page
describes what it generates, why it is shaped that way, and how to walk an
audience through it.

## Running it

```bash
make demo-up      # preflight, Postgres + Redis, demo up, demo change, API, worker, web, then verify
make demo-verify  # assert the estate still has every shape the walkthrough shows
make demo-down    # demo down, then stop the containers

# The underlying commands:
uv run kestrel demo up          # generate + sync four tenants, seed operator-side data
uv run kestrel demo change      # replay the three-month drift timeline
uv run kestrel demo down --yes  # remove the tenants and everything derived from them
uv run kestrel demo verify      # non-zero exit if a demo beat has no subject
```

The first `make demo-up` also builds the api, worker, and web images, which
takes several minutes. After that, `demo up` and `demo change` together take a
few minutes; most of it is the timeline's repeated syncs and policy
evaluations.

`demo verify` is the guard against a silent regression: it checks that four
tenants are connected and synced, that the anchor personas exist, that at
least one person is correlated across three or more applications, and that the
cross-app policies have open findings. A generator or timeline edit that
removes a demo beat fails here rather than in front of an audience.

`kestrel init --seed` remains the fast minimal path (GitHub fixtures only, a
few seconds). Use it for smoke checks; use `demo up` for anything you intend
to look at. In a local checkout, sign in as `admin@kestrel.local` /
`kestrel-dev-password` ([`getting-started.md`](getting-started.md)); a Docker
deployment never gets that default, and a bare `kestrel init` prints a random
password once instead (`--dev-password` opts a checkout into the default).

## Where the data comes from

The shipped `connectors/*/fixtures/` trees stay small and hand-readable; they
are the CI contract artifact (`test_fixture_contract.py`,
`kestrel connector validate`). The demo instead generates a much larger tree at
run time into a temporary directory and hands it to each connector through
the `build_fixture_transport(fixtures_dir=…)` override. Generation is driven
by one seeded `random.Random`, so two machines produce byte-identical
fixtures and therefore an identical demo. `demo change` regenerates the same
baseline rather than persisting it.

Because that tree only exists while the CLI runs, the demo instances (labelled
"(demo)") cannot be synced from the UI, the API, or a schedule: a plain fixture
sync would read the small shipped sample and delete most of the demo. Sync now
is disabled on them and the API answers 409; refresh them with `demo change`.

| Module | Role |
|--------|------|
| `kestrel/src/kestrel/demo/personas.py` | The roster: one cast, projected into each tenant |
| `kestrel/src/kestrel/demo/generate.py` | Per-connector fixture emitters |
| `kestrel/src/kestrel/demo/timeline.py` | The drift steps and their order |
| `kestrel/src/kestrel/demo/backdate.py` | Moves completed runs into the past |
| `kestrel/src/kestrel/demo/seed_product.py` | Everything connectors cannot produce |
| `kestrel/src/kestrel/demo/teardown.py` | `demo down` |

## The roster

One hundred fictional people, defined once and projected into GitHub, Slack,
Okta, and Google Workspace. Email is the join key, because it is what the
identity graph collapses on, so the same person carries one address everywhere
they appear. Under half are in all four tenants; the rest are in one to three,
including a few who exist only in Google Workspace and a few with no identity
provider account at all -- which is what gives the cross-app graph, and the
`cross-app-no-idp-account` policy, something to say.

Each persona has an archetype, and the archetypes exist so the shipped policy
packs have real subjects:

| Archetype | What it demonstrates |
|-----------|----------------------|
| `admin_no_mfa` | The highest-severity posture finding in every pack |
| `admin` | Ordinary privileged users, for contrast |
| `dormant` | No login in months |
| `deprovisioned_admin` | Disabled, still holding a super-admin role: orphaned privilege |
| `departed` | Offboarded accounts |
| `external` | Outside collaborators and guests |
| `service_account` | Non-human identities |
| `staff` | The majority, so the findings above stand out |

Five anchors keep stable names for walkthroughs: **Grace Hopper** (admin
without MFA), **Ada Lovelace** (admin), **Alan Turing** (staff, escalated
during the timeline), **Katherine Johnson** (dormant, then offboarded), and a
contractor on a vendor domain.

## Volume

| Tenant | Generated |
|--------|-----------|
| GitHub | ~65 members, ~9 outside collaborators, 40 repositories, 12 teams, 60 audit entries |
| Slack | ~72 users, 10 user groups, 24 apps, 15 channels, 4 workspaces, 50 audit entries |
| Okta | ~87 users, 12 groups, 20 apps, 55 System Log entries |
| Google Workspace | ~67 users, 8 groups, 4 organizational units, 3 shared drives, ~83 OAuth grants, login and token report events |

That lands as a few hundred identities and a few hundred open findings after
the drift timeline, with people correlated across as many as four applications.

## The timeline

`demo change` replays seven steps spanning about 74 days on a baseline dated
96 days back — the three-month drift timeline the other pages refer to — one
sync per step per affected tenant, each back-dated afterwards. Steps are cumulative, so
replaying from the generated baseline keeps history consistent without
storing intermediate trees.

| Step | Days ago | What happens |
|------|----------|--------------|
| Contractor onboarding | 74 | Contractor gets admin on a sensitive repository; Slack Connect to a new vendor; team and read grants |
| Quarterly access drift | 62 | Team membership churn; Alan promoted to Okta Super Administrator |
| Shadow IT install | 50 | Over-scoped third-party Slack app; Threat Insight setting changed |
| Offboarding | 38 | Katherine deprovisioned in Okta, removed from GitHub, suspended in Google Workspace — and deliberately left alone in Slack, which is the subject of `cross-app-departed-still-has-access` |
| MFA regression | 26 | Ada's MFA factors removed; public repository creation enabled org-wide |
| Scope creep | 14 | Slack app scopes expanded; an app uninstalled; a permission reduced and one revoked; a Google Workspace user consents to an app with Gmail and Drive scopes, and a group opens to external members |
| Privilege expansion | 2 | Alan promoted in GitHub, Slack, and Google Workspace (Super Admin); Grace granted repository admin; a grant escalated |

Two things about the ordering are deliberate. The newest step opens findings
rather than resolving them, because the default seven-day Changes window and
the youngest finding-age bucket both look broken if the most recent event was
someone leaving. And significance is mixed: privilege grants and the
over-scoped install rank at the top of `/changes` while membership churn and
demotions sort below them, because a feed where everything is high ranks
nothing. Together the steps cover all eighteen change classes
([`changes.md`](changes.md)).

## Back-dating

Timestamps are rewritten after each run commits rather than by passing a
clock into `run_sync`. Deletion detection compares `last_seen_at` with the
run's start, and `last_seen_at` is set independently during upsert, so
back-dating only the run would silently disable deletion detection for every
seeded step. Rewriting afterwards cannot desynchronize the two because the
diff has already been computed. The baseline install is dated 96 days back so
findings that have existed since the tenant was connected land in the oldest
age bucket while drift findings fill the newer ones.

## Operator-side data

Syncs produce inventory, graph, changes, and findings. Everything an operator
does afterwards is written only by API handlers, so a sync-only demo leaves a
dozen working features as empty states. `seed_product.py` fills them: findings
across all five statuses with about forty percent assigned and some muted with
expiries; notes, watchers, and exceptions; five extra operators across every
role, one inactive (they share `kestrel-dev-password` in a local checkout and
have no password at all on a deployment, so nobody can sign in as them); three webhook endpoints with about fifty deliveries across
success, failure, and pending; two ticket integrations and about ten tickets;
about ninety days of posture-trend snapshots; and about three hundred
audit-log entries, which also populate the finding-detail activity timeline.

Webhook endpoints and ticket integrations store an encrypted secret and need
`KESTREL_MASTER_KEY`; a bare `kestrel demo up` does not load `.env`, so
without the key the seed reports what it skipped rather than failing.

## Teardown

`demo down` is a full cascade, and has to be: `connector_runs` rows are
referenced NOT NULL from fifteen tables, so "remove the connector but keep
its inventory" is not representable. Teardown removes the tenants and
everything derived from them in dependency order while keeping the
organization, operators, policies, and packs, so `demo up` restores a clean
estate without re-bootstrapping the install.

It also keeps what the product seed wrote that is not derived from a tenant:
the demo team operators, dashboards, saved finding filters, posture-trend
snapshots, audit-log rows, webhook endpoints, ticket integrations and AI
settings. A following `demo up` reuses them rather than duplicating them. To
start from nothing, use `make db-reset CONFIRM=yes` (development stack only)
and run `demo up` again.

## Walking someone through it

A twenty-minute walkthrough that holds together on fixtures alone; a live
tenant substitutes for any beat when one is available.

Before starting: `make demo-up` (which ends by running `demo verify`), sign
in, and confirm the four demo integrations show under Integrations.

1. **Integrations** (2 min). Show the configured integrations; open one, run Test connection, and show a recent successful sync with its run detail.
2. **Identities** (3 min). Search a name; one row per person with the applications they hold accounts in. Open one: accounts across applications with their state, access grouped by application, groups, findings, and recent activity. Katherine Johnson is the offboarding story — disabled in Okta and Google Workspace, still active in Slack.
3. **Explore** (5–7 min). Search `Grace`: one identity spanning Okta, Slack, and GitHub. Ask "what can they reach?" across apps and point out direct, inherited, and OAuth-derived hops. The inspector's Accounts list shows the correlated accounts. Focus the Okta `engineering` group with direction `both` for members on one side and apps on the other.
4. **Changes** (5 min). The drift timeline is already loaded by `make demo-up`; run `make demo-change` to stack another cycle (or flip a real privilege or sharing setting in a vendor console and sync). Show the classified rows: new admin, privilege escalation, OAuth install, external sharing, with before → after evidence.
5. **Connector SDK** (3 min). Open a `connectors/*/manifest.yaml`; show `required_scopes` and that the loader refuses write scopes. Four first-party connectors plus an example custom connector, one SDK.
6. **Architecture** (remaining). Python policies, per-sync snapshots alongside the events diff, honest limits: no write-back, intra-sync misses stated in the UI.

| If a beat fails | Do |
|-----------------|----|
| Live sync 429, auth error, or no network | `kestrel demo fallback <app> --to fixtures` |
| Explore is empty | Re-run `demo up`; use the privileged-identity picker |
| Changes is empty | Run `demo change` once; hard-refresh `/changes` |
| Stale UI after a rebuild | Hard refresh or rebuild the web image |
| Anything looks thin before you start | `make demo-verify` names what is missing |

## Falling back from live to fixtures

Where an application has both a live instance and a fixture instance,
`kestrel demo fallback <app> --to fixtures` makes the fixture one active and
pauses the live one: the paused instance is marked disabled and its schedule
is remembered and cleared, so it cannot wake up mid-demo. `--to live` reverses
it, restoring the schedule. `kestrel demo status` prints which side is active
for every application.

Nothing is faked by this. The fixture side is the same generated estate the
offline demo uses and stays labeled as sample data everywhere it appears; the
live side keeps its own data and is one command away. If an application has
only one instance, the command says so and changes nothing rather than
pretending to switch.

Reset between runs with `make demo-down` then `make demo-up`. Never point a
walkthrough at a production tenant; use dedicated demo orgs.

## Extending it

- More people: raise `roster_size` or add anchors to `_ANCHORS` in `personas.py`.
- More of one tenant: the `repo_count` / `team_count` / `app_count` / `channel_count` arguments on the per-connector generators.
- A new drift beat: write a step in `timeline.py` and add it to `TIMELINE`. Steps resolve people by email and return `[]` when they cannot, so `tests/unit/test_demo_timeline.py` asserts every step produces drift; a step that silently does nothing fails the suite.
- Another tenant: add a `_DemoTenant` in `cli/demo.py`, a generator in `generate.py`, and the tenant name to `_tenants_for` in `personas.py`.
- A new demo-critical shape: add an assertion to `kestrel demo verify` so a later edit cannot remove it silently.
