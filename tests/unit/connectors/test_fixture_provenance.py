# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Every field that produces a setting must come from somewhere real.

Four connectors shipped settings derived from fields their providers do not
return -- Google Workspace 2SV enforcement and Drive sharing, four Slack
workspace settings, Okta MFA enrollment. The values existed only in fixtures, so
the whole offline suite passed while the checks were dead on a live tenant, and
two of them raised high-severity false positives.

Reading fixtures did not catch that, four times. This does, by splitting the
problem in half:

*Automatically*, it derives which payload fields a normalizer actually consumes
to emit a `setting` -- drop a key, see whether the emitted settings change. No
one has to keep a list of what the code reads in sync with the code.

*By hand*, `connectors/<name>/fixtures/PROVENANCE.yaml` declares whether the
provider really returns that field. That claim cannot be derived from the
repository; it is the one thing a human has to get right, and this test forces
it to be written down and reviewed rather than implied by a fixture.

Setting-emitting object types are discovered from the connectors themselves, so
a new one with no provenance entry fails rather than slipping through.
"""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from kestrel.connectors.sdk.base import RawObject

# (package, connector class, config, fixture-transport args)
CONNECTORS: dict[str, tuple[str, str, dict[str, Any], tuple[Any, ...]]] = {
    "github": ("kestrel_connector_github", "GitHubConnector", {"org_login": "acme-corp"}, ("acme-corp",)),
    "okta": ("kestrel_connector_okta", "OktaConnector", {"org_url": "https://acme.okta.com"}, ()),
    "slack": ("kestrel_connector_slack", "SlackConnector", {"team_id": "T0ACMEWORK"}, ("T0ACMEWORK",)),
    "google_workspace": (
        "kestrel_connector_google_workspace",
        "GoogleWorkspaceConnector",
        {"domain": "acme.example.com"},
        ("acme.example.com",),
    ),
}

_CONNECTORS_DIR = Path(__file__).resolve().parents[3] / "connectors"


def _provenance_path(name: str) -> Path:
    return _CONNECTORS_DIR / name / "fixtures" / "PROVENANCE.yaml"


def _load_provenance(name: str) -> dict[str, Any]:
    path = _provenance_path(name)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()).get("sources") or {}


def _settings_signature(normalizer: Any, object_type: str, raw: RawObject) -> Any:
    """Emitted settings as a comparable value, or a marker when normalization
    raises -- a field whose removal breaks the normalizer is consumed too."""
    try:
        return sorted(
            (o.attributes.get("key"), json.dumps(o.attributes.get("value"), default=str))
            for o in normalizer.normalize(object_type, raw)
            if o.kind == "setting"
        )
    except Exception as exc:  # noqa: BLE001 - any failure means the field mattered
        return ("__raised__", type(exc).__name__)


def _build(name: str) -> tuple[Any, Any]:
    package, class_name, config, transport_args = CONNECTORS[name]
    connector = getattr(importlib.import_module(f"{package}.connector"), class_name)()
    connector.configure(config)
    fixture_transport = importlib.import_module(f"{package}.fixture_transport")
    transport = fixture_transport.build_fixture_transport(*transport_args)
    return connector.build_collector(transport), connector.build_normalizer()


def _derive(name: str) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """object_type -> (payload fields the settings depend on, setting keys that
    depend on no field at all).

    The second half exists because perturbation alone has a blind spot, and the
    Okta bug sat exactly in it: `setdefault("mfa_enroll_required", bool(None))`
    emitted the same `False` whatever the payload contained, so removing any
    field changed nothing and the fabrication looked like it had no source. A
    setting that depends on nothing is either a deliberate existence signal or
    invented, and the difference has to be written down.
    """
    collector, normalizer = _build(name)
    consumed: dict[str, set[str]] = {}
    constant: dict[str, set[str]] = {}
    for object_type in collector.discover():
        fields: set[str] = set()
        always: set[str] | None = None
        emits = False
        for raw in collector.collect(object_type):
            baseline = _settings_signature(normalizer, object_type, raw)
            if not isinstance(baseline, list) or not baseline:
                continue
            emits = True
            survivors = {key for key, _ in baseline}
            for key in list(raw.payload.keys()):
                payload = copy.deepcopy(raw.payload)
                payload.pop(key)
                probe = RawObject(
                    object_type=object_type,
                    provider_id=raw.provider_id,
                    payload=payload,
                    collected_at=raw.collected_at,
                )
                probed = _settings_signature(normalizer, object_type, probe)
                if probed != baseline:
                    fields.add(key)
                # A setting key surviving every removal, unchanged, is constant.
                survivors &= {k for k, _ in probed} if isinstance(probed, list) else set()
                if isinstance(probed, list):
                    survivors &= {k for k, v in probed if (k, v) in baseline}
            always = survivors if always is None else (always & survivors)
        if emits:
            consumed[object_type] = fields
            constant[object_type] = always or set()
    return consumed, constant


def _consumed_fields(name: str) -> dict[str, set[str]]:
    return _derive(name)[0]


# Computed once: driving every connector's fixtures is the expensive part.
_DERIVED = {name: _derive(name) for name in CONNECTORS}
_CONSUMED = {name: fields for name, (fields, _) in _DERIVED.items()}
_CONSTANT = {name: const for name, (_, const) in _DERIVED.items()}


def _ids(name: str) -> list[str]:
    return sorted(_CONSUMED[name])


@pytest.mark.parametrize("connector", sorted(CONNECTORS))
def test_every_setting_emitting_object_type_declares_its_provenance(connector: str) -> None:
    declared = set(_load_provenance(connector))
    emitting = set(_CONSUMED[connector])
    missing = sorted(emitting - declared)
    assert not missing, (
        f"{connector}: {missing} emit settings with no entry in "
        f"{_provenance_path(connector).relative_to(_CONNECTORS_DIR.parent)}. "
        "Add the endpoint, a docs link, and the fields it returns."
    )


@pytest.mark.parametrize("connector", sorted(CONNECTORS))
def test_no_setting_is_built_from_an_undeclared_field(connector: str) -> None:
    """The regression that shipped four times."""
    provenance = _load_provenance(connector)
    problems: list[str] = []
    for object_type, fields in sorted(_CONSUMED[connector].items()):
        entry = provenance.get(object_type)
        if entry is None:
            continue  # reported by the coverage test above
        allowed = set(entry.get("returns") or []) | set(entry.get("synthetic") or {})
        for field in sorted(fields - allowed):
            problems.append(
                f"  {object_type}: '{field}' produces a setting but is not declared. "
                f"Either {entry.get('endpoint', '<endpoint>')} really returns it "
                f"(add to `returns`, and check the docs page, not the fixture), "
                f"or the collector injects it (add to `synthetic` with the reason), "
                f"or the fixture invented it."
            )
    assert not problems, f"{connector}: undeclared setting sources\n" + "\n".join(problems)


@pytest.mark.parametrize("connector", sorted(CONNECTORS))
def test_provenance_does_not_declare_fields_nothing_reads(connector: str) -> None:
    """A stale `returns` entry is a claim nobody is checking any more."""
    provenance = _load_provenance(connector)
    stale: list[str] = []
    for object_type, entry in sorted(provenance.items()):
        consumed = _CONSUMED[connector].get(object_type)
        if consumed is None:
            stale.append(f"  {object_type}: declared but emits no settings")
            continue
        for field in sorted(set(entry.get("returns") or []) - consumed):
            stale.append(f"  {object_type}: declares '{field}' in `returns`, but no setting depends on it")
    assert not stale, f"{connector}: stale provenance\n" + "\n".join(stale)


def test_the_derivation_actually_finds_fields() -> None:
    """Guard: a perturbation loop that silently finds nothing would pass everything."""
    total = sum(len(fields) for conn in _CONSUMED.values() for fields in conn.values())
    assert total > 20, f"only {total} consumed fields derived across all connectors — the probe is not working"


@pytest.mark.parametrize("connector", sorted(CONNECTORS))
def test_every_declared_entry_names_an_endpoint_and_a_docs_link(connector: str) -> None:
    for object_type, entry in sorted(_load_provenance(connector).items()):
        assert entry.get("endpoint"), f"{connector}/{object_type}: no endpoint"
        docs = entry.get("docs") or ""
        assert docs.startswith("https://"), f"{connector}/{object_type}: no docs link"


@pytest.mark.parametrize("connector", sorted(CONNECTORS))
def test_a_setting_that_depends_on_no_field_is_declared_constant(connector: str) -> None:
    """Closes the blind spot perturbation leaves open.

    The Okta bug lived here: a `setdefault` fallback produced the same value
    whatever the payload held, so no field looked responsible for it. Requiring
    every such setting to be named makes "this value comes from nowhere" a
    sentence somebody has to write and a reviewer has to accept.
    """
    provenance = _load_provenance(connector)
    problems: list[str] = []
    for object_type, keys in sorted(_CONSTANT[connector].items()):
        declared = set((provenance.get(object_type) or {}).get("constant") or {})
        for key in sorted(keys - declared):
            problems.append(
                f"  {object_type}: setting '{key}' is emitted with the same value no matter "
                f"what the payload contains. If that is deliberate (an existence signal), "
                f"declare it under `constant` with the reason. If it is a default standing in "
                f"for a field the provider never returned, it is the Okta bug again."
            )
    assert not problems, f"{connector}: undeclared constant settings\n" + "\n".join(problems)
