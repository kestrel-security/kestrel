# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for cursor arithmetic (`sync.cursors`).

The DB-touching half lives in tests/integration/test_sync_incremental.py;
these cover the pure decisions: what a manifest declares as incrementally
collectable, and how an opaque cursor is handled.
"""

from __future__ import annotations

from kestrel.connectors.sdk.manifest import ConnectorManifest, ObjectTypeSpec
from kestrel.sync.cursors import incremental_object_types


def _manifest(**object_types: bool) -> ConnectorManifest:
    return ConnectorManifest(
        name="fake",
        display_name="Fake",
        version="0.0.0",
        description="d",
        auth_methods=[],
        object_types=[
            ObjectTypeSpec(name=name, maps_to_entity="event", supports_incremental=incremental)
            for name, incremental in object_types.items()
        ],
    )


def test_only_object_types_declaring_incremental_are_polled():
    manifest = _manifest(system_log=True, user=False)
    assert incremental_object_types(manifest) == ["system_log"]


def test_a_connector_declaring_none_is_not_polled():
    assert incremental_object_types(_manifest(user=False)) == []


def test_the_stored_manifest_dict_works_too():
    # The beat dispatcher has only the Connector row's JSONB manifest; making
    # it import every connector package just to decide who to poll would be
    # backwards.
    stored = {
        "object_types": [
            {"name": "audit_log", "maps_to_entity": "event", "supports_incremental": True},
            {"name": "user", "maps_to_entity": "identity"},
        ]
    }
    assert incremental_object_types(stored) == ["audit_log"]


def test_an_empty_or_missing_manifest_is_not_an_error():
    assert incremental_object_types({}) == []
    assert incremental_object_types({"object_types": None}) == []
