# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Manifest-to-normalizer contract checks.

A manifest's ``object_types[].maps_to_entity`` is a promise about what the
normalizer emits for that object type. Nothing enforced it, so four first-party
manifests had drifted: `application_instance` (an entity the sync pipeline never
writes -- the row is created out of band when the instance is configured) and
`tenant_setting` (the *table* name; the kind is `setting`) were both in use, and
Okta's `app_group` claimed `grant` while emitting `oauth_grant`.

This is not cosmetic. `maps_to_entity` is what `kestrel.changes.coverage.
infer_change_classes` reads to decide which ChangeClasses a connector is on the
hook for, and what `kestrel connector validate` reads to decide whether a
connector claiming `supports_events` actually collects any. A manifest that
misdescribes its kinds gets the wrong coverage contract applied to it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kestrel.connectors.sdk.manifest import ConnectorManifest


def persistable_kinds() -> frozenset[str]:
    """Normalized kinds the sync pipeline actually writes.

    Read from `sync.upsert` rather than duplicated, so a kind added to the
    pipeline cannot silently stay invalid in manifests. Imported lazily --
    `sync.upsert` pulls in the whole DB model layer, and the SDK is imported by
    connector packages that have no reason to load it.
    """
    from kestrel.sync.upsert import NORMALIZED_KINDS

    return NORMALIZED_KINDS


def check_entity_mapping(manifest: ConnectorManifest, kinds_by_object_type: dict[str, set[str]]) -> list[str]:
    """Problems with this manifest's `maps_to_entity` declarations.

    `kinds_by_object_type` comes from a fixture-mode `CollectionResult`. An
    object type the run never reached is skipped rather than reported -- absence
    of evidence, and the fixture contract already fails a manifest entry the
    fixtures never exercise.

    Returns one human-readable line per problem; empty means the manifest
    describes what the normalizer emits.
    """
    valid = persistable_kinds()
    problems: list[str] = []

    for spec in manifest.object_types:
        claimed = spec.maps_to_entity
        if claimed not in valid:
            problems.append(
                f"{spec.name}: maps_to_entity '{claimed}' is not a kind the sync "
                f"pipeline persists (valid: {', '.join(sorted(valid))})"
            )
            continue

        emitted = kinds_by_object_type.get(spec.name)
        if emitted is None:
            continue
        if claimed not in emitted:
            problems.append(f"{spec.name}: manifest claims '{claimed}' but the normalizer emits {sorted(emitted) or '[]'}")

    return problems
