# Connector Authoring Tutorial

This is both a specification of the Kestrel Connector SDK and a step-by-step tutorial for building a new connector. It uses `kestrel connector create` and the GitHub connector (`connectors/github/`) as reference implementations throughout — read this alongside that code.

## Why the SDK is shaped this way

A connector is built by implementing four things, tied together by one top-level class:

- **`Transport`** — how requests are made. You never write this; you use `LiveHTTPTransport` (real HTTP, from `kestrel.connectors.sdk.transport`) or `FixtureTransport` (replays canned JSON, from `kestrel.connectors.sdk.fixtures`). The protocols themselves live in `kestrel.connectors.sdk.base`.
- **`Collector`** — pulls `RawObject`s (untouched provider JSON, tagged with an object type and provider id) from the source system, via a `Transport`.
- **`Normalizer`** — a pure function from `RawObject` to one or more `NormalizedObject`s (Kestrel entities) plus any `NormalizedRelationship`s (graph edges) they imply. No I/O — this is what makes normalization logic trivially unit-testable.
- **`Connector`** — wires configuration, authentication, and the collector/normalizer together.

These are `typing.Protocol`s (see ADR-0005), not base classes to subclass — any object with the right methods satisfies the contract. The Transport indirection is what makes "testable entirely against fixtures with no live credentials" literally true: a `Collector` is constructed with a `FixtureTransport` in every unit test, and never imports `httpx`.

## Quick start: scaffold a connector

```
kestrel connector create my-app
```

This generates `connectors/my-app/` (or wherever `--dir` points) with a **working** template — not empty stubs. It has one real object type (`user`, mapped to `identity`), a fixture file, a passing unit test, an example policy, and a README. Validate it immediately, with zero credentials:

```
kestrel connector validate connectors/my-app
```

This loads `manifest.yaml`, checks the declared fixtures directory exists, and runs the real collector + normalizer against `fixtures/` via a `FixtureTransport` — reporting object counts and normalized-object counts. `kestrel connector validate` works on a freshly scaffolded connector *before* it's registered anywhere: `kestrel.connectors.discovery.load_connector_from_path` adds the connector's `src/` to `sys.path` and finds the class implementing the `Connector` protocol by checking for the right attributes, not by guessing a class name from the connector's own name (a naive `"github"` → `"Github"` PascalCase conversion would miss the real `GitHubConnector`).

Run the scaffold's own test. The repository's default `uv run pytest` run does
not collect under `connectors/`, so name the path:

```
uv run pytest connectors/my-app/tests
```

## The manifest (`manifest.yaml`)

```yaml
name: my-app
display_name: My App
version: "0.1.0"
description: >
 What this connector collects and why.
auth_methods:
 - id: api_key
 label: "API Key"
 secret_fields: [api_key] # never logged, sent to an LLM, or returned by the API
 config_fields: [base_url] # non-secret; safe to store and display
required_scopes: []
object_types:
 - name: user
 maps_to_entity: identity
 supports_incremental: false
rate_limit_strategy: fixed_delay # or "header_based"
supports_events: false
change_classes: # the change-coverage contract; see "Change coverage" below
 - identity_added
example_config:
 base_url: "https://api.example.com"
fixtures_path: fixtures/
```

`secret_fields` is not cosmetic: `kestrel.secrets.store.redact` uses it to recursively scrub matching keys from any object before it's logged, sent to an AI provider, or returned via the API — declare every field that could contain a credential.

### Setup walkthroughs (required for first-party connectors)

Every auth method should include an end-to-end setup guide so **Integrations → Add integration** can walk operators through minting PATs / API keys / Apps:

```yaml
auth_methods:
 - id: api_key
 label: "API Key"
 secret_fields: [api_key]
 config_fields: [base_url]
 setup_overview: Short intro for this auth method.
 scopes_note: Optional elaboration of required_scopes.
 field_help:
 base_url: Where to find this value in the provider UI.
 api_key: What to paste; remind that it is encrypted at rest.
 setup_steps:
 - title: Open the provider console
 body: Concrete clicks / navigation.
 link_url: https://example.com/admin/api-keys
 link_label: Provider API keys
 - title: Create a read-only key
 body: Scopes and options to select.
 - title: Paste into Kestrel and test
 body: Config + Secrets steps, then Test connection / Sync now.
setup_docs: docs/connectors/my-app-setup.md # optional long-form doc path
```

`GET /api/v1/connectors` returns these fields for the create/detail UI. See GitHub's guide: `docs/connectors/github-setup.md`.

## Implementing collection

`client.py` is a thin typed wrapper over a `Transport`. Every method's path (including any query string) doubles as the exact request signature `FixtureTransport` uses to find its matching fixture file:

```python
class MyAppClient:
 def __init__(self, transport: Transport, base_url: str) -> None:
 self.transport = transport
 self.base_url = base_url

 def list_users(self) -> list[dict[str, Any]]:
 return list(self.transport.paginate("GET", "/users"))
```

`collector.py` translates client responses into `RawObject`s, one per manifest object type:

```python
def _collect_user(self, now: datetime) -> Iterable[RawObject]:
 for user in self.client.list_users():
 yield RawObject(object_type="user", provider_id=str(user["id"]), payload=user, collected_at=now)
```

If your source system needs cross-referencing between endpoints before yielding an object (e.g. GitHub's normalizer needs to know both a member's org role *and* their 2FA status, which come from two different endpoints), do that enrichment in the collector, so the normalizer can stay a pure single-object mapping function. See `connectors/github/src/kestrel_connector_github/collector.py`'s `_collect_member` for a real example.

With more than one object type, dispatch `collect` to one `_collect_<object_type>` method per type rather than growing an `if`/`elif` chain; every first-party collector does this (`connectors/slack/src/kestrel_connector_slack/collector.py` is a compact example).

If a payload carries a URL that may embed a credential (a webhook or callout endpoint), redact it in the collector with `kestrel.connectors.sdk.payload.reduce_url_to_host(config, "url")`, which keeps only `url_host` and `url_scheme`. `raw_source` is stored verbatim, so anything left in the payload is persisted.

## Classifying failures: skip, fail, or report

A live sync meets three kinds of failure, and treating them alike is the most common connector bug:

- **A permission or plan gate** (usually 403 or 404 on one object family): record it in `skipped_object_types` and keep collecting.
- **A rate limit:** never skippable. Dropping a family because the token was throttled reports an incomplete inventory as complete, and deletion detection then reads the missing rows as mass revocation.
- **Anything else:** fail the run.

`kestrel.connectors.sdk.failures` has the shared pieces. Your connector supplies only what is provider-specific, usually its `is_rate_limit` predicate:

```python
from kestrel.connectors.sdk.failures import classify_http_failure, http_status, is_skippable_gate


def is_rate_limit(exc: BaseException) -> bool:
    # Your provider's throttle shape. A plain 429 is the SDK default.
    return http_status(exc) == 429


def is_skippable(exc: BaseException) -> bool:
    return is_skippable_gate(exc, is_rate_limit=is_rate_limit)


def classify_failure(exc: BaseException) -> str:
    # "authentication", "permission", "rate_limit", "http_<status>", "network" or "unknown"
    return classify_http_failure(exc, is_rate_limit=is_rate_limit)
```

If your API reports errors in the body rather than the status (Slack's `ok: false`, GitHub's GraphQL `errors`), handle those first and fall through to `classify_http_failure`; see `connectors/slack/src/kestrel_connector_slack/health.py`.

A classified health check runs one cheap probe per required permission, collects `{probe label: failure class}`, and turns the failures into one operator-facing message with `summarize_probe_failures`. It applies the same precedence for every provider (authentication, then permission, then rate limit, then network); you write the wording:

```python
from kestrel.connectors.sdk.failures import FailureMessages, summarize_probe_failures

_FAILURE_MESSAGES = FailureMessages(
    authentication="Authentication failed for: {probes}. Rotate the API key.",
    permission="Permission denied for: {probes}. Grant the read-only admin role.",
    rate_limit="Rate limited for: {probes}. Retry after the reset window.",
    network="Network error for: {probes}. Check base_url and outbound HTTPS.",
    fallback="API error for: {probes}",
)

message = summarize_probe_failures(failures, _FAILURE_MESSAGES)
```

`{probes}` becomes a list such as `users.list (permission), roles.list (permission)`. A message that depends on which probes failed, such as naming the missing scopes, can be a function `(probes, failures) -> str`; see `connectors/github/src/kestrel_connector_github/health.py`.

## Implementing normalization

`normalizer.py` maps a `RawObject` into `NormalizedObject`s. Reference the attribute names your `_entity_kwargs`-equivalent expects — see `kestrel/src/kestrel/sync/upsert.py`'s `_entity_kwargs` for the exact attribute set each `kind` needs (`identity`, `group`, `role`, `resource`, `permission`).

```python
def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    return [
        NormalizedObject(
            kind="identity",
            provider_id=raw.provider_id,
            attributes={
                "identity_type": "user",
                "display_name": payload.get("name"),
                "email": payload.get("email"),
                "is_disabled": False,
                "is_external": False,
                "mfa_enabled": None,
            },
            raw_source=payload,
        )
    ]
```

To produce a graph edge (e.g. group membership, resource access), attach a `NormalizedRelationship` to the relevant `NormalizedObject`:

```python
NormalizedObject(
    kind="group_membership",
    provider_id=f"{team_id}:{member_id}",
    attributes={"group_ref": team_id, "identity_ref": member_id},
    raw_source=payload,
    relationships=[
        NormalizedRelationship(edge_type="member_of", source_ref=member_id, target_ref=team_id, access_path="direct"),
    ],
)
```

`source_ref`/`target_ref` are the *provider's own ids*, not Kestrel ids — they get resolved to real graph node ids by `kestrel.graph.writer` once every object in the collection run has been upserted. **Important**: this resolution is flattened across all entity kinds within one run, so your connector's provider ids must be unique across object types (true for GitHub; if your source system reuses ids across types, namespace your `provider_id`s, e.g. `f"user:{id}"` vs `f"repo:{id}"`).

## Writing fixtures

Capture (and anonymize) real API responses, one JSON file per endpoint, in `fixtures/`. Build a `FixtureTransport` mapping request signatures to files:

```python
def build_fixture_transport() -> FixtureTransport:
    return FixtureTransport(
        fixtures_dir=FIXTURES_DIR,
        mapping={"GET /users": "users.json"},
    )
```

For connectors with per-item requests (e.g. per-repo collaborator lists), build the mapping programmatically — see `connectors/github/src/kestrel_connector_github/fixture_transport.py` for a real example with a fixed set of teams/repos.

## Change coverage

`/changes` is a black-box recorder over sync diffs (DEC-024). If your connector
collects privilege, OAuth grants, or security settings, those drifts must show
up as named ChangeClasses. Declare them on the manifest (or let validate infer
from `maps_to_entity`):

```yaml
change_classes:
 - admin_granted
```

Ship a `fixtures/changed/` overlay (only the files that differ). `kestrel
connector validate` collects t0 from `fixtures/`, merges `fixtures/changed/`
for t1, diffs normalized objects, and **fails** if a claimed class is missing.

Rules of thumb:

- Privileged role assignments must emit a `grant` with `role_ref` and/or
 `permission_level=admin` — a graph edge alone is not coverage.
- `supports_events: false` is fine; audit logs feed optional event policies in Findings,
 not a requirement for Changes.
- The scaffold claims `identity_added` and includes `fixtures/changed/users.json`
 with one extra user so validate passes out of the box.

### `maps_to_entity` must name a kind you actually emit

`maps_to_entity` is not a label — it is what `validate` reads to infer your
coverage contract, so getting it wrong applies the wrong contract to your
connector. It must be one of the kinds the sync pipeline persists:

```
identity · group · role · resource · permission · setting · event
group_membership · grant · oauth_application · oauth_scope · oauth_grant
```

Two near-misses are worth calling out because four first-party manifests had
them before `validate` started catching them:

- **`application_instance`** is not one. That row is created out of band when
 the connector instance is configured; an org or team payload that produces
 tenant configuration maps to `setting`.
- **`tenant_setting`** is the *table*. The kind is `setting`.

`kestrel connector validate` fails on both, and on a kind your normalizer does
not emit for that object type.

## Writing tests

Unit-test the normalizer directly (no DB, no network — feed it a `RawObject`, assert the `NormalizedObject`s it produces). Optionally, test the collector + normalizer together via `kestrel.connectors.sdk.runner.run_collection` with your `FixtureTransport`, asserting object counts and specific normalized attributes — see `tests/unit/connectors/test_run_collection.py`.

A connector contributed to this repository keeps its Tier 1 tests in `tests/unit/connectors/` (for example `test_<name>_normalizer.py` and `test_<name>_collector.py`), not in `connectors/<name>/tests/`, so CI and the default run collect them. The shared fixture contract in `tests/unit/connectors/test_fixture_contract.py` covers every installed connector automatically. See [`../testing.md`](../testing.md).

## Writing an example policy

Your scaffold includes `example_policy.py` (Panther-style `policy(resource) -> bool`). Validate it:

```
kestrel policy validate connectors/my-app/example_policy.py
```

See `docs/policies.md` and ADR-0009. First-party connectors often split live `health.py` from the collector; the scaffold inlines `health_check` on the collector, which is enough until you need classified live probes.

Live HTTP from a connector should go through `LiveHTTPTransport` so SSRF checks apply. Do not open raw `httpx` clients to operator-supplied URLs.

`kestrel.connectors.sdk.credentials` covers the repetitive parts of `auth.py`: `first_secret(secrets, "api_token", "token")` picks the first non-empty secret when you accept legacy field names, `bearer_headers(token)` builds `Authorization: Bearer` plus `Accept: application/json`, and `normalize_pem(key)` repairs a private key pasted with literal `\n` escapes. Which secrets you accept, and in what order, stays in your connector.

## Wiring in for real use

A scaffolded connector works standalone (via `sys.path` injection) for `kestrel connector validate` and its own tests, but to use it through `kestrel sync`, the API, or the worker, it needs to be a real installed package:

1. Add the connector's directory to the root `pyproject.toml`'s `[tool.uv.workspace].members`.
2. Run `uv sync` from the repo root. This installs the connector in editable mode and registers its `kestrel.connectors` entry point (declared in the connector's own `pyproject.toml`):
 ```toml
 [project.entry-points."kestrel.connectors"]
 my-app = "kestrel_connector_my_app.connector:MyAppConnector"
 ```
3. `kestrel.connectors.sdk.registry.discover_connectors()` (used by `kestrel sync`, the worker, and the API) now finds it by name — Kestrel's core code never imports a specific connector directly.

Alternatively, set `KESTREL_CUSTOM_CONNECTORS_DIR` to a directory of connector packages (each with `manifest.yaml`). Those appear in Integrations under **Custom** without a Dockerfile edit. `examples/custom-connector` is the reference package for this path.

## Design constraints to keep in mind

- **Never send credentials or unrestricted raw records to an LLM.** If you build an AI-assisted feature touching this connector's data, route it through `kestrel.secrets.store.redact` first.
- **Preserve the raw source object.** Every `NormalizedObject.raw_source` is stored verbatim as the entity's `raw_source` column — don't discard fields you don't currently normalize; a future policy or evidence field might need them.
- **Idempotency matters.** Entity upserts are keyed by `(application_instance_id, provider_object_id)` — re-running a sync with unchanged data must not create duplicate rows (see `tests/integration/test_pipeline_sync.py::test_rerunning_sync_is_idempotent` for the pattern your connector's data should satisfy too).
