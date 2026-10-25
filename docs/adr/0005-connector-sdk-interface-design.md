# ADR-0005: Connector SDK Interface Design

## Status

Accepted

## Context

The Connector SDK is one of the most important parts of Kestrel: the product principle "connector development should be easy" means a security engineer must be able to build a connector for an internal application without modifying Kestrel's core, and test it entirely against fixtures with zero live credentials.

## Decision

- **Structural `Protocol`s (`typing.Protocol`, `@runtime_checkable`), not ABC inheritance**, for the core contracts: `Connector`, `Collector`, `Normalizer`, `Transport` (`kestrel/connectors/sdk/base.py`). A connector author's classes don't need to subclass a specific Kestrel base class — any object with the right methods satisfies the contract. This lowers the barrier for third-party/internal connector authors and makes test doubles trivial to write. `BaseRESTCollector`-style ABCs with real default behavior (pagination helpers, etc.) remain a reasonable future addition *on top of* the Protocol contract, not instead of it.
- **YAML manifests** (`manifest.yaml`), validated by a Pydantic model (`ConnectorManifest`). YAML is more approachable for non-Python security engineers than TOML for the nested structures a manifest needs (auth methods, object type lists), and matches the format most existing connector ecosystems (Airbyte, Singer) already use.
- **Fixture/live mode via an injected `Transport`**, not a mode flag threaded through every method. `LiveHTTPTransport` wraps `httpx`; `FixtureTransport` replays canned JSON keyed by an exact request signature (`METHOD path`, including any query string) read from the connector's `fixtures/` directory. A `Collector` never imports `httpx` directly — it only calls `self.transport.request(...)`/`.paginate(...)`. This is the mechanism that makes "testable entirely against fixtures with no live credentials" concretely true rather than aspirational: unit tests instantiate a collector with a `FixtureTransport`, full stop.
- **`configure()` is a separate lifecycle step from `authenticate()`.** Non-secret configuration (e.g. an org login) must be available to the collector regardless of which Transport is in play, but `authenticate()` (which builds a live Transport from config + secrets) should never run in fixture mode. `kestrel.connectors.sdk.runner.run_collection` always calls `connector.configure(config)`, then uses a supplied `transport_override` if given, only falling back to `connector.authenticate(config, secrets)` for live mode.
- **Connector discovery has two paths**, both implemented: `kestrel.connectors.sdk.registry` discovers *installed* connectors via the `kestrel.connectors` Python entry-point group (no direct import of any specific connector by core code); `kestrel.connectors.discovery.load_connector_from_path` loads a connector directly from a directory by structurally duck-typing the `Connector` protocol (checking for `manifest`/`configure`/`authenticate`/`build_collector`/`build_normalizer`), which is what lets `kestrel connector validate` work immediately after `kestrel connector create`, before a contributor has registered the new package as a workspace member.

## Why

- Protocol-based contracts plus dependency-injected transports are the two decisions that jointly deliver "connector development without modifying core" and "testable with zero credentials" as literal, verifiable properties of the codebase — not just design intentions. The GitHub connector's own test suite never imports `httpx` or touches the network, and `kestrel connector create` scaffolds a connector whose generated unit test passes before a single line is customized.
- Duck-typing over class-name guessing in `discovery.py` avoids a real footgun: naive PascalCase conversion of a connector's name (`"github"` → `"Github"`) doesn't match irregular capitalization (`GitHubConnector`), so any naming-convention-based discovery mechanism would need constant special-casing. Structural checks sidestep the problem entirely.

## Consequences

- Every connector package must expose exactly one class satisfying the `Connector` protocol's five required attributes; `discovery.py` raises a clear error if none (or, implicitly, if more than one is found, whichever `dir()` happens to return first) is present.
- `FixtureTransport`'s exact-match request-signature lookup means fixture mappings are connector-specific and hand-maintained (see `connectors/github/src/kestrel_connector_github/fixture_transport.py`), not automatically inferred from live traffic — a acceptable v1 tradeoff since fixture authoring is a one-time cost per connector, done once by whoever builds it.
