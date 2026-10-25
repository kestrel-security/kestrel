# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Orchestrates the connector lifecycle: configure -> authenticate (live
mode only) -> discover -> collect -> normalize.

Persistence (upserting into entity tables, graph writer, event diffing) is
layered on top by the worker's sync task -- this module only produces
normalized data in memory, it never touches the DB. That keeps it usable
both from the worker and from `kestrel connector validate` / unit tests.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kestrel.connectors.sdk.base import Connector, NormalizedObject, RawObject, Transport


@dataclass
class CollectionResult:
    object_type_counts: dict[str, int] = field(default_factory=dict)
    normalized_objects: list[NormalizedObject] = field(default_factory=list)
    raw_objects: list[RawObject] = field(default_factory=list)
    # Object types (or sub-families) the connector could not read on this run,
    # mapped to a coarse failure class. Populated from the collector's optional
    # `skipped_object_types` attribute -- see `run_collection`.
    skipped_object_types: dict[str, str] = field(default_factory=dict)
    # Normalized kinds each object type actually emitted. `normalized_objects`
    # is flat, so the association is otherwise lost -- and it is what proves a
    # manifest's `maps_to_entity` describes reality rather than intent.
    kinds_by_object_type: dict[str, set[str]] = field(default_factory=dict)


def run_collection(
    connector: Connector,
    *,
    config: dict[str, Any],
    secrets: dict[str, str] | None = None,
    transport_override: Transport | None = None,
    since: datetime | None = None,
    since_by_object_type: Mapping[str, datetime] | None = None,
    object_types: Collection[str] | None = None,
) -> CollectionResult:
    """Runs one collection pass for a connector instance.

    If `transport_override` is given (typically a FixtureTransport), it is
    used instead of calling connector.authenticate() -- this is what lets
    `kestrel connector validate` and unit tests run with zero credentials.
    `connector.configure(config)` still runs in both cases, since non-secret
    config (e.g. an org login) is needed by the collector regardless of
    which Transport is in play.

    `object_types` narrows the run to a subset of what `discover()` offers --
    how the events-only poll collects audit logs every few minutes without
    re-walking the whole directory. A narrowed run is not a full inventory;
    callers must suppress deletion detection for it (see `sync.pipeline`).
    Names not offered by `discover()` are ignored rather than raising, since a
    connector may degrade a family it cannot read on this credential.

    `since_by_object_type` supplies a per-object-type watermark, which is the
    granularity the manifest declares `supports_incremental` at. `since` stays
    as the fallback for every type without an entry.
    """
    connector.configure(config)
    transport = transport_override or connector.authenticate(config, secrets or {})
    collector = connector.build_collector(transport)
    normalizer = connector.build_normalizer()

    discovered = collector.discover()
    if object_types is not None:
        wanted = set(object_types)
        discovered = [name for name in discovered if name in wanted]

    result = CollectionResult()
    for object_type in discovered:
        count = 0
        kinds: set[str] = set()
        watermark = since
        if since_by_object_type is not None:
            watermark = since_by_object_type.get(object_type, since)
        for raw in collector.collect(object_type, since=watermark):
            result.raw_objects.append(raw)
            normalized = normalizer.normalize(object_type, raw)
            kinds.update(obj.kind for obj in normalized)
            result.normalized_objects.extend(normalized)
            count += 1
        result.object_type_counts[object_type] = count
        result.kinds_by_object_type[object_type] = kinds

    # Optional, duck-typed: a collector that degrades plan- or permission-gated
    # families instead of raising records them here. Connectors that always
    # fail hard simply don't define it.
    skipped = getattr(collector, "skipped_object_types", None)
    if isinstance(skipped, dict):
        result.skipped_object_types = dict(skipped)
    return result
