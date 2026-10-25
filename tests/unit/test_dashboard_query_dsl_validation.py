# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- the dashboard metric DSL rejects specs outside its allowlist.

Every rejection here happens before a query is built, so the session handed to
``execute_query`` is a stand-in that fails the test if it is ever touched.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from kestrel.dashboard.query_dsl import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    QuerySpec,
    execute_query,
    parse_query_spec,
)
from pydantic import ValidationError


class _UntouchableSession:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the DSL touched the database ({name}) for a spec it should reject")


ORG = uuid.uuid4()


def _run(spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return execute_query(_UntouchableSession(), org_id=ORG, spec=spec, **kwargs)  # type: ignore[arg-type]


def test_limit_defaults_and_is_capped_at_the_maximum():
    assert parse_query_spec({"entity": "finding"}).limit == DEFAULT_LIMIT
    assert parse_query_spec({"entity": "finding", "limit": MAX_LIMIT * 10}).limit == MAX_LIMIT
    assert parse_query_spec({"entity": "finding", "limit": 1}).limit == 1


@pytest.mark.parametrize("limit", [0, -5])
def test_limit_below_one_is_rejected(limit: int):
    with pytest.raises(ValidationError, match="limit must be >= 1"):
        parse_query_spec({"entity": "finding", "limit": limit})


def test_entity_is_required_without_a_preset():
    with pytest.raises(ValidationError, match="entity is required"):
        parse_query_spec({"filters": []})


@pytest.mark.parametrize(
    "spec",
    [
        {"entity": "users"},
        {"entity": "finding", "filters": [{"field": "status", "op": "like", "value": "o%"}]},
        {"entity": "finding", "metric": {"fn": "sum"}},
        {"entity": "finding", "order_by": [{"field": "count", "dir": "sideways"}]},
    ],
)
def test_values_outside_the_literal_allowlists_are_rejected(spec: dict[str, Any]):
    with pytest.raises(ValidationError):
        parse_query_spec(spec)


def test_parse_passes_an_already_parsed_spec_through():
    spec = QuerySpec(entity="finding")
    assert parse_query_spec(spec) is spec


def test_a_preset_spec_returns_an_empty_preset_payload_without_querying():
    result = _run({"preset": "posture_overview"})
    assert result == {
        "kind": "preset",
        "preset": "posture_overview",
        "series": [],
        "rows": [],
        "total": 0,
        "drilldown": {},
    }


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"entity": "finding", "group_by": ["title"]}, "group_by not allowed for finding: title"),
        (
            {"entity": "finding", "filters": [{"field": "raw_source", "value": "x"}]},
            "filter field not allowed: raw_source",
        ),
        (
            {"entity": "finding", "filters": [{"field": "status", "op": "in", "value": "open"}]},
            "in requires a list value",
        ),
        (
            {"entity": "finding", "filters": [{"field": "status", "op": "not_in", "value": "open"}]},
            "not_in requires a list value",
        ),
        (
            {"entity": "finding", "filters": [{"field": "application_type", "op": "neq", "value": "slack"}]},
            "application_type filter requires op=eq",
        ),
        (
            {"entity": "finding", "filters": [{"field": "application_type", "value": ["slack"]}]},
            "application_type filter requires op=eq",
        ),
        (
            {"entity": "finding", "filters": [{"field": "application_type", "value": "myspace"}]},
            "unknown application_type: myspace",
        ),
        (
            {"entity": "finding", "filters": [{"field": "application_instance_id", "value": "not-a-uuid"}]},
            "invalid application_instance_id",
        ),
        (
            {"entity": "finding", "filters": [{"field": "assigned_to_operator_id", "value": "me"}]},
            "viewer required for assigned_to_operator_id=me",
        ),
        (
            {"entity": "finding", "time_range": {"field": "resolved_at", "last": "7d"}},
            "time_range.field not allowed: resolved_at",
        ),
        (
            {"entity": "finding", "time_range": {"last": "2w"}},
            "unsupported time_range.last: 2w",
        ),
        ({"entity": "connector", "group_by": ["name"]}, "group_by not allowed for connector: name"),
        (
            {"entity": "connector", "group_by": ["health", "sync_mode"]},
            "connector queries group by at most one field",
        ),
        (
            {"entity": "connector", "filters": [{"field": "config", "value": "x"}]},
            "filter field not allowed: config",
        ),
        (
            {"entity": "connector", "filters": [{"field": "health", "op": "gt", "value": "healthy"}]},
            "filter op not allowed for connector: gt",
        ),
        (
            {"entity": "posture_trend", "filters": [{"field": "status", "value": "open"}]},
            "posture_trend does not support filters or group_by",
        ),
        (
            {"entity": "posture_trend", "group_by": ["status"]},
            "posture_trend does not support filters or group_by",
        ),
    ],
)
def test_invalid_specs_raise_value_error_before_touching_the_database(spec: dict[str, Any], message: str):
    with pytest.raises(ValueError, match=message):
        _run(spec)
