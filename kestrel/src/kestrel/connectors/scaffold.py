# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel connector create <name>` -- generates a working connector
template: manifest, auth, collector, normalizer, fixtures, a passing unit
test, an example policy, and a README. It targets a trivial example API (a
single "user" object type) so the scaffold is genuinely runnable and
testable against its own fixtures immediately, with zero credentials --
customizing it for a real application means editing client.py/collector.py/
normalizer.py, not starting from nothing.
"""

from __future__ import annotations

import re
from pathlib import Path


def _pascal_case(name: str) -> str:
    return "".join(word.capitalize() for word in re.split(r"[-_]", name) if word)


def scaffold_connector(name: str, parent_dir: Path) -> Path:
    package = name.replace("-", "_")
    pascal = _pascal_case(name)
    display_name = name.replace("-", " ").replace("_", " ").title()
    target = parent_dir / name

    if target.exists():
        raise FileExistsError(f"{target} already exists")

    (target / "src" / f"kestrel_connector_{package}").mkdir(parents=True)
    (target / "fixtures").mkdir()
    (target / "tests").mkdir()

    _write(target / "manifest.yaml", _MANIFEST_TEMPLATE.format(name=name, display_name=display_name))
    _write(target / "pyproject.toml", _PYPROJECT_TEMPLATE.format(name=name, package=package, pascal=pascal))
    _write(
        target / "README.md",
        _README_TEMPLATE.format(name=name, display_name=display_name, package=package, pascal=pascal),
    )
    _write(target / "example_policy.py", _POLICY_TEMPLATE.format(name=name, display_name=display_name))

    pkg_dir = target / "src" / f"kestrel_connector_{package}"
    _write(pkg_dir / "__init__.py", "")
    _write(pkg_dir / "auth.py", _AUTH_TEMPLATE)
    _write(pkg_dir / "client.py", _CLIENT_TEMPLATE.format(pascal=pascal, display_name=display_name))
    _write(pkg_dir / "collector.py", _COLLECTOR_TEMPLATE.format(package=package, pascal=pascal))
    _write(pkg_dir / "normalizer.py", _NORMALIZER_TEMPLATE.format(pascal=pascal))
    _write(pkg_dir / "connector.py", _CONNECTOR_TEMPLATE.format(package=package, pascal=pascal))
    _write(pkg_dir / "fixture_transport.py", _FIXTURE_TRANSPORT_TEMPLATE)

    _write(target / "fixtures" / "users.json", _FIXTURE_USERS_JSON)
    (target / "fixtures" / "changed").mkdir()
    _write(target / "fixtures" / "changed" / "users.json", _FIXTURE_USERS_CHANGED_JSON)
    _write(target / "tests" / "__init__.py", "")
    _write(target / "tests" / "conftest.py", _CONFTEST_TEMPLATE)
    _write(target / "tests" / "test_normalizer.py", _TEST_TEMPLATE.format(package=package, pascal=pascal))

    return target


def _write(path: Path, content: str) -> None:
    path.write_text(content)


_MANIFEST_TEMPLATE = """\
name: {name}
display_name: {display_name}
version: "0.1.0"
description: >
  Example Kestrel connector scaffold for {display_name}. Replace the
  auth/client/collector/normalizer implementations with real calls to your
  application's API -- this template ships with one object type ("user")
  mapped to identities, enough to prove the wiring end-to-end.
auth_methods:
  - id: api_key
    label: "API Key"
    secret_fields: [api_key]
    config_fields: [base_url]
    setup_overview: >
      Create an API key in your application's admin console, then paste it
      into Kestrel. Replace these setup_steps with real vendor instructions
      before shipping the connector.
    field_help:
      base_url: API base URL (HTTPS). Must pass Kestrel's SSRF guard.
      api_key: Provider API key. Envelope-encrypted; never shown after save.
    setup_steps:
      - title: Open the provider admin console
        body: >
          Sign in as an admin who can create API keys for the tenant you want
          Kestrel to monitor.
      - title: Create a read-only API key
        body: >
          Generate a key with the least privileges needed to list users (and
          other object types you will collect). Prefer read-only scopes.
      - title: Copy the key into Kestrel
        body: >
          Paste the key into api_key on the Secrets step. Set base_url on
          Config. Choose live sync mode, then Test connection / Sync now.
required_scopes: []
object_types:
  - name: user
    maps_to_entity: identity
rate_limit_strategy: fixed_delay
supports_events: false
change_classes:
  - identity_added
example_config:
  base_url: "https://api.example.com"
fixtures_path: fixtures/
"""

_PYPROJECT_TEMPLATE = """\
[project]
name = "kestrel-connector-{name}"
version = "0.1.0"
description = "Kestrel connector for {name}."
license = {{text = "Apache-2.0"}}
requires-python = ">=3.12"
dependencies = [
    "kestrel",
]

[project.entry-points."kestrel.connectors"]
{name} = "kestrel_connector_{package}.connector:{pascal}Connector"

[tool.uv.sources]
kestrel = {{ workspace = true }}

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/kestrel_connector_{package}"]
"""

_README_TEMPLATE = """\
# Kestrel Connector: {display_name}

Generated by `kestrel connector create {name}`. Replace the example API calls
in `client.py`, `collector.py`, and `normalizer.py` with real calls to your
application.

## Local validation (zero credentials)

    kestrel connector validate .

This runs the collector + normalizer against `fixtures/` via a
FixtureTransport -- no network access, no secrets required.

## Testing

    uv run pytest tests/

## Wiring in for real use

1. Add this directory to the root `pyproject.toml`'s `[tool.uv.workspace]`
   members list.
2. Run `uv sync` from the repo root -- this registers the
   `kestrel.connectors` entry point declared in this connector's
   `pyproject.toml`, so `kestrel sync` and the API can discover it by name
   ("{name}").
3. See `example_policy.py` for a starting point on policies over this
   connector's data (`kestrel policy validate example_policy.py`).
"""

_POLICY_TEMPLATE = """\
POLICY_ID = "{name}-user-without-mfa"
TITLE = "Example policy: flag {display_name} users without MFA"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Example policy: flag {display_name} users without MFA -- customize this for your real policy logic"
REMEDIATION = "Enable MFA for this user."


def policy(resource):
    identity = resource.get("identity") or {{}}
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {{}}
    return {{
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
    }}
"""

_AUTH_TEMPLATE = """\
from kestrel.connectors.sdk.transport import LiveHTTPTransport


def build_live_transport(config: dict, secrets: dict[str, str]) -> LiveHTTPTransport:
    return LiveHTTPTransport(
        base_url=config["base_url"],
        headers={"Authorization": f"Bearer {secrets['api_key']}"},
    )
"""

_CLIENT_TEMPLATE = """\
\"\"\"Thin typed wrapper over a Transport. Replace these methods with real
calls to {display_name}'s API -- every method's path doubles as the request
signature FixtureTransport uses to find its matching fixture file.\"\"\"

from __future__ import annotations

from typing import Any

from kestrel.connectors.sdk.base import Transport


class {pascal}Client:
    def __init__(self, transport: Transport, base_url: str) -> None:
        self.transport = transport
        self.base_url = base_url

    def list_users(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", "/users"))
"""

_COLLECTOR_TEMPLATE = """\
\"\"\"Translates {pascal}Client responses into RawObjects, one per manifest
object_type.\"\"\"

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject

from kestrel_connector_{package}.client import {pascal}Client

OBJECT_TYPES = ["user"]


class {pascal}Collector:
    def __init__(self, client: {pascal}Client) -> None:
        self.client = client

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        users = self.client.list_users()
        return HealthCheckResult(healthy=True, message=f"Connected, found {{len(users)}} users")

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        if object_type != "user":
            raise ValueError(f"Unsupported object_type '{{object_type}}'")
        now = datetime.now(UTC)
        for user in self.client.list_users():
            yield RawObject(object_type="user", provider_id=str(user["id"]), payload=user, collected_at=now)
"""

_NORMALIZER_TEMPLATE = """\
\"\"\"Maps RawObjects into Kestrel NormalizedObjects. Pure function-ish: no
I/O, fully unit-testable without network or DB access.\"\"\"

from __future__ import annotations

from kestrel.connectors.sdk.base import NormalizedObject, RawObject


class {pascal}Normalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        if object_type != "user":
            raise ValueError(f"Unsupported object_type '{{object_type}}'")
        payload = raw.payload
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes={{
                    "identity_type": "user",
                    "display_name": payload.get("name"),
                    "email": payload.get("email"),
                    "is_disabled": False,
                    "is_external": False,
                    "mfa_enabled": None,
                }},
                raw_source=payload,
            )
        ]
"""

_CONNECTOR_TEMPLATE = """\
\"\"\"Top-level {pascal}Connector, wiring configure/authenticate/
build_collector/build_normalizer together. Discovered via the
`kestrel.connectors` entry point declared in pyproject.toml once this
connector is added to the workspace and `uv sync` has run.\"\"\"

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_{package}.auth import build_live_transport
from kestrel_connector_{package}.client import {pascal}Client
from kestrel_connector_{package}.collector import {pascal}Collector
from kestrel_connector_{package}.normalizer import {pascal}Normalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class {pascal}Connector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._config: dict[str, Any] = {{}}

    def configure(self, config: dict[str, Any]) -> None:
        self._config = config

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        return build_live_transport(config, secrets)

    def build_collector(self, transport: Transport) -> Collector:
        client = {pascal}Client(transport, base_url=self._config.get("base_url", ""))
        return {pascal}Collector(client)

    def build_normalizer(self) -> Normalizer:
        return {pascal}Normalizer()
"""

_FIXTURE_TRANSPORT_TEMPLATE = """\
\"\"\"Builds a FixtureTransport for this connector's bundled fixtures/, used
by unit tests and `kestrel connector validate` to prove it works with zero
live credentials.\"\"\"

from __future__ import annotations

from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureTransport

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


def build_fixture_transport(fixtures_dir: str | Path | None = None) -> FixtureTransport:
    return FixtureTransport(
        fixtures_dir=fixtures_dir or FIXTURES_DIR,
        mapping={"GET /users": "users.json"},
    )
"""

_FIXTURE_USERS_JSON = """\
[
  {"id": 1, "name": "Ada Lovelace", "email": "ada@example.com"},
  {"id": 2, "name": "Grace Hopper", "email": "grace@example.com"}
]
"""

_FIXTURE_USERS_CHANGED_JSON = """\
[
  {"id": 1, "name": "Ada Lovelace", "email": "ada@example.com"},
  {"id": 2, "name": "Grace Hopper", "email": "grace@example.com"},
  {"id": 3, "name": "Alan Turing", "email": "alan@example.com"}
]
"""

_CONFTEST_TEMPLATE = """\
# Puts this connector's src/ on the path for its tests. The connector is not
# installed until it is added to the uv workspace (see README.md), and the
# repository runs pytest with --import-mode=importlib, which does not add test
# directories to sys.path.

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
"""

_TEST_TEMPLATE = """\
from datetime import UTC, datetime

from kestrel.connectors.sdk.base import RawObject
from kestrel_connector_{package}.normalizer import {pascal}Normalizer


def test_normalize_user():
    normalizer = {pascal}Normalizer()
    raw = RawObject(
        object_type="user",
        provider_id="1",
        payload={{"id": 1, "name": "Ada Lovelace", "email": "ada@example.com"}},
        collected_at=datetime.now(UTC),
    )

    objects = normalizer.normalize("user", raw)

    assert len(objects) == 1
    assert objects[0].kind == "identity"
    assert objects[0].attributes["email"] == "ada@example.com"
"""
