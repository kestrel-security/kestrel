# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for FixtureTransport's volatile-parameter fallback.

Okta and Slack have both plumbed `collect(since=)` to their audit clients
since they shipped, and neither path had any offline coverage: the cursored
request carries a timestamp that changes every run, so no exact-match fixture
signature could ever match it. Nothing caught that because nothing ever passed
`since`.
"""

from __future__ import annotations

import json

import pytest
from kestrel.connectors.sdk.fixtures import FixtureNotFoundError, FixtureTransport


@pytest.fixture
def fixtures_dir(tmp_path):
    (tmp_path / "logs.json").write_text(json.dumps([{"id": "e1"}, {"id": "e2"}]))
    return tmp_path


def _transport(fixtures_dir, **kwargs) -> FixtureTransport:
    return FixtureTransport(
        fixtures_dir=fixtures_dir,
        mapping={"GET /logs?limit=200&sortOrder=DESCENDING": "logs.json"},
        **kwargs,
    )


def test_a_cursored_request_resolves_to_the_uncursored_fixture(fixtures_dir):
    transport = _transport(fixtures_dir, volatile_params={"since"})
    rows = transport.request("GET", "/logs?limit=200&sortOrder=DESCENDING&since=2026-08-30T12:00:00Z")
    assert [row["id"] for row in rows] == ["e1", "e2"]


def test_the_uncursored_request_still_matches_exactly(fixtures_dir):
    transport = _transport(fixtures_dir, volatile_params={"since"})
    assert transport.request("GET", "/logs?limit=200&sortOrder=DESCENDING")


def test_without_the_declaration_a_cursored_request_still_misses(fixtures_dir):
    # The fallback is opt-in per connector; it must not quietly loosen
    # exact-match lookup for every connector.
    transport = _transport(fixtures_dir)
    with pytest.raises(FixtureNotFoundError):
        transport.request("GET", "/logs?limit=200&sortOrder=DESCENDING&since=2026-08-30T12:00:00Z")


def test_only_the_named_parameters_are_stripped(fixtures_dir):
    transport = _transport(fixtures_dir, volatile_params={"since"})
    with pytest.raises(FixtureNotFoundError):
        # `limit` differs, so this is a genuinely different call.
        transport.request("GET", "/logs?limit=50&sortOrder=DESCENDING&since=2026-08-30T12:00:00Z")


def test_remaining_parameter_order_is_preserved(fixtures_dir):
    # The stripped signature has to reproduce the registered one exactly.
    transport = _transport(fixtures_dir, volatile_params={"since", "oldest"})
    assert transport.request("GET", "/logs?limit=200&since=2026-08-30T12:00:00Z&sortOrder=DESCENDING")


def test_paginate_uses_the_same_fallback(fixtures_dir):
    transport = _transport(fixtures_dir, volatile_params={"since"})
    rows = list(transport.paginate("GET", "/logs?limit=200&sortOrder=DESCENDING&since=2026-08-30T12:00:00Z"))
    assert len(rows) == 2
