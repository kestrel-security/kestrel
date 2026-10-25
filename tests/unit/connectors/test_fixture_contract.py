# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-connector fixture contract (docs/testing.md rule 2 /
DEC-024): exactly one test per connector, asserting that its
bundled fixture set (a) normalizes without error, (b) discovers every object
type its manifest declares, (c) declares a `maps_to_entity` per object type
that names a kind the pipeline persists *and* the normalizer actually emits, and (d) covers every ChangeClass it claims via
`fixtures/ -> fixtures/changed/`. No other test in this tier may assert on
the *content* of a shipped fixture.

Discovery goes through `kestrel.connectors.sdk.registry.discover_connectors`
(the same entry-point registry `kestrel sync` and the worker use) rather than
globbing `connectors/*/fixtures/` -- so this file never hardcodes a fixture
path, matching the rule that broke three tests in the old suite when
`packs/core/policies` was deleted out from under a hardcoded path. The
per-connector fixtures directory itself is derived from the connector
module's own `__file__` plus `manifest.fixtures_path`, exactly as
`kestrel connector validate` derives it for a path-loaded connector
(kestrel/src/kestrel/cli/connector.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from kestrel.changes.coverage import infer_change_classes, validate_change_coverage
from kestrel.connectors.sdk.contract import check_entity_mapping, persistable_kinds
from kestrel.connectors.sdk.registry import discover_connectors, load_fixture_transport_builder
from kestrel.connectors.sdk.runner import run_collection


def _connector_names() -> list[str]:
    return sorted(discover_connectors())


def _package_root(connector_class: type) -> Path:
    """The connector package directory (e.g. `connectors/github/`), found by
    introspecting the module the connector class is defined in -- never a
    literal `connectors/<name>` string."""
    module = sys.modules[connector_class.__module__]
    module_file = getattr(module, "__file__", None)
    assert module_file, f"{connector_class!r} has no resolvable module file"
    # <package_root>/src/<package>/connector.py -> parents[2] is <package_root>.
    return Path(module_file).resolve().parents[2]


@pytest.mark.parametrize("connector_name", _connector_names())
def test_connector_fixture_contract(connector_name: str) -> None:
    registration = discover_connectors()[connector_name]
    connector_class = registration.connector_class
    manifest = connector_class.manifest
    build_fixture_transport = load_fixture_transport_builder(connector_name)

    fixtures_dir = _package_root(connector_class) / manifest.fixtures_path
    assert fixtures_dir.is_dir(), f"{connector_name}: manifest.fixtures_path {manifest.fixtures_path!r} does not exist"

    connector = connector_class()
    result = run_collection(
        connector,
        config=dict(manifest.example_config),
        transport_override=build_fixture_transport(),
    )

    # (a) normalizes without error: run_collection above already raised if any
    # RawObject failed to normalize -- reaching this line proves it did not.

    # (b) discovers every object type the manifest declares, and each one
    # actually produced rows -- a manifest entry the bundled fixtures never
    # exercise is exactly the gap this contract exists to catch.
    manifest_object_types = {ot.name for ot in manifest.object_types}
    discovered_object_types = set(result.object_type_counts)
    missing_types = manifest_object_types - discovered_object_types
    assert not missing_types, (
        f"{connector_name}: manifest declares object_types {sorted(missing_types)} "
        "that the fixture-mode collector never discovered"
    )
    zero_row_types = {ot for ot, count in result.object_type_counts.items() if count == 0}
    assert not zero_row_types, f"{connector_name}: fixtures produced zero rows for {sorted(zero_row_types)}"

    # (c) every `maps_to_entity` names a kind the pipeline persists, and one
    # this object type's normalizer actually emits. `maps_to_entity` is what
    # `infer_change_classes` reads to decide the coverage contract, so a
    # manifest that misdescribes its kinds gets the wrong contract applied.
    mapping_problems = check_entity_mapping(manifest, result.kinds_by_object_type)
    assert not mapping_problems, f"{connector_name}: " + "; ".join(mapping_problems)

    # (d) covers every ChangeClass it claims, via fixtures -> fixtures/changed.
    claimed = infer_change_classes(manifest)
    if not claimed:
        return
    coverage = validate_change_coverage(
        connector=connector,
        manifest=manifest,
        fixtures_dir=fixtures_dir,
        build_fixture_transport=build_fixture_transport,
    )
    assert coverage.changed_fixtures_used, (
        f"{connector_name}: claims {sorted(coverage.claimed)} but {fixtures_dir / 'changed'} is missing"
    )
    assert coverage.ok, (
        f"{connector_name}: claims {sorted(coverage.claimed)}, observed "
        f"{sorted(coverage.observed)}, missing {sorted(coverage.missing)}"
    )


def test_at_least_the_first_party_connectors_were_discovered() -> None:
    # A guard against the parametrization above silently collecting zero
    # cases (e.g. entry points not installed) and reporting a false "0
    # passed, 0 failed" green run.
    discovered = set(_connector_names())
    assert {"github", "google_workspace", "slack", "okta"} <= discovered


def test_entity_mapping_check_rejects_a_kind_the_pipeline_never_persists() -> None:
    """Guard: the contract above must actually bite.

    `application_instance` and `tenant_setting` were both live in first-party
    manifests -- one names an entity created out of band when the connector
    instance is configured, the other names the *table* backing the `setting`
    kind. Neither is anything a normalizer can emit.
    """
    from kestrel.connectors.sdk.manifest import ConnectorManifest, ObjectTypeSpec

    manifest = ConnectorManifest(
        name="fake",
        display_name="Fake",
        version="0.0.0",
        description="fixture for the contract check",
        auth_methods=[],
        object_types=[
            ObjectTypeSpec(name="org", maps_to_entity="application_instance"),
            ObjectTypeSpec(name="policy", maps_to_entity="tenant_setting"),
        ],
    )

    problems = check_entity_mapping(manifest, {"org": {"setting"}, "policy": {"setting"}})
    assert len(problems) == 2
    assert all("is not a kind the sync pipeline persists" in p for p in problems)


def test_entity_mapping_check_rejects_a_valid_kind_the_normalizer_does_not_emit() -> None:
    from kestrel.connectors.sdk.manifest import ConnectorManifest, ObjectTypeSpec

    manifest = ConnectorManifest(
        name="fake",
        display_name="Fake",
        version="0.0.0",
        description="fixture for the contract check",
        auth_methods=[],
        object_types=[ObjectTypeSpec(name="app_group", maps_to_entity="grant")],
    )

    problems = check_entity_mapping(manifest, {"app_group": {"oauth_grant"}})
    assert problems == ["app_group: manifest claims 'grant' but the normalizer emits ['oauth_grant']"]


def test_entity_mapping_check_skips_object_types_the_run_never_reached() -> None:
    """A gated family reduces the run; it must not read as a mapping error.

    The zero-row assertion in the contract above already catches a manifest
    entry the fixtures never exercise.
    """
    from kestrel.connectors.sdk.manifest import ConnectorManifest, ObjectTypeSpec

    manifest = ConnectorManifest(
        name="fake",
        display_name="Fake",
        version="0.0.0",
        description="fixture for the contract check",
        auth_methods=[],
        object_types=[ObjectTypeSpec(name="audit_log", maps_to_entity="event")],
    )

    assert check_entity_mapping(manifest, {}) == []


def test_persistable_kinds_covers_the_relationship_reconciliation_path() -> None:
    """`oauth_scope` is in neither PROVENANCE_KINDS nor RELATIONSHIP_KINDS.

    It is reconciled against its owning application inside
    `upsert_relationship_objects`, so deriving the vocabulary from those two
    tuples alone would reject a mapping four connectors legitimately declare.
    """
    kinds = persistable_kinds()
    assert {"oauth_scope", "setting", "grant"} <= kinds
    assert "discovered_application" not in kinds
    assert "application_instance" not in kinds
    assert "tenant_setting" not in kinds
