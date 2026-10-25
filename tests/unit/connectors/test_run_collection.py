# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the two duck-typed seams in `run_collection`.

Both are contracts between a connector and the sync pipeline that nothing
enforces at type-check time:

* ``skipped_object_types`` is read with ``getattr``, so a rename in the runner
  or a typo in a collector silently disables degradation -- the run reports
  SUCCESS over a partial inventory and `detect_deletions` reads the gap as
  revocation.
* ``kinds_by_object_type`` is what proves a manifest's ``maps_to_entity``
  describes reality; ``normalized_objects`` is flat, so without it
  the object-type association is gone.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult, NormalizedObject, RawObject
from kestrel.connectors.sdk.runner import run_collection


class _Collector:
    def __init__(self, *, skipped: Any = None, define_skipped: bool = True) -> None:
        if define_skipped:
            self.skipped_object_types = skipped if skipped is not None else {}

    def discover(self) -> list[str]:
        return ["identity", "setting"]

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterator[RawObject]:
        yield RawObject(
            object_type=object_type,
            provider_id=f"{object_type}-1",
            payload={},
            collected_at=datetime.now(UTC),
        )

    def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(healthy=True, message="ok")


class _Normalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        # One object type legitimately emitting two kinds -- an identity
        # that also carries its admin role, the GitHub `member` shape.
        kinds = ["identity", "role"] if object_type == "identity" else ["setting"]
        return [
            NormalizedObject(kind=kind, provider_id=f"{raw.provider_id}:{kind}", attributes={}, raw_source={})
            for kind in kinds
        ]


class _Connector:
    manifest = None

    def __init__(self, collector: _Collector) -> None:
        self._collector = collector

    def configure(self, config: dict[str, Any]) -> None:
        pass

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Any:
        raise NotImplementedError("transport_override is always supplied here")

    def build_collector(self, transport: Any) -> _Collector:
        return self._collector

    def build_normalizer(self) -> _Normalizer:
        return _Normalizer()


def _run(collector: _Collector):
    return run_collection(_Connector(collector), config={}, transport_override=object())


def test_skipped_object_types_reaches_the_collection_result() -> None:
    result = _run(_Collector(skipped={"audit_log": "permission"}))
    assert result.skipped_object_types == {"audit_log": "permission"}


def test_the_skip_map_is_copied_not_aliased() -> None:
    # The pipeline holds the result past the collector's lifetime.
    collector = _Collector(skipped={"audit_log": "permission"})
    result = _run(collector)
    collector.skipped_object_types["late"] = "permission"
    assert result.skipped_object_types == {"audit_log": "permission"}


def test_a_collector_without_the_attribute_reports_no_skips() -> None:
    # Connectors that always fail hard simply do not define it.
    result = _run(_Collector(define_skipped=False))
    assert result.skipped_object_types == {}


def test_a_non_dict_attribute_is_ignored_rather_than_crashing_the_run() -> None:
    result = _run(_Collector(skipped=["audit_log"]))
    assert result.skipped_object_types == {}


def test_kinds_are_recorded_per_object_type() -> None:
    result = _run(_Collector())
    assert result.kinds_by_object_type == {"identity": {"identity", "role"}, "setting": {"setting"}}
    # The flat list is unchanged; the map is additive.
    assert len(result.normalized_objects) == 3


def test_object_type_counts_count_raw_objects_not_normalized_ones() -> None:
    result = _run(_Collector())
    assert result.object_type_counts == {"identity": 1, "setting": 1}
