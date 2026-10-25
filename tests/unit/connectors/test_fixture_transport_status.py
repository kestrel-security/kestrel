# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for FixtureTransport's status mapping and raw path.

A fixture set used to be able to express only success-with-a-JSON-body and
failure. GitHub's vulnerability-alerts probe answers 204 No Content when alerts
are enabled, which is neither, so the bundled fixture said ``{}`` where live
said nothing, and the live-only decode failure stayed invisible offline.
"""

from __future__ import annotations

import json

import pytest
from kestrel.connectors.sdk.base import request_raw
from kestrel.connectors.sdk.fixtures import FixtureHTTPError, FixtureStatus, FixtureTransport


@pytest.fixture
def transport(tmp_path) -> FixtureTransport:
    (tmp_path / "org.json").write_text(json.dumps({"login": "acme"}))
    return FixtureTransport(
        fixtures_dir=tmp_path,
        mapping={
            "GET /orgs/acme": "org.json",
            "GET /repos/acme/web-app/vulnerability-alerts": FixtureStatus(204),
            "GET /repos/acme/docs/vulnerability-alerts": FixtureStatus(404),
        },
    )


def test_a_2xx_status_is_a_success_with_no_body(transport: FixtureTransport) -> None:
    assert transport.request("GET", "/repos/acme/web-app/vulnerability-alerts") is None


def test_a_4xx_status_still_raises_a_classifiable_error(transport: FixtureTransport) -> None:
    with pytest.raises(FixtureHTTPError) as excinfo:
        transport.request("GET", "/repos/acme/docs/vulnerability-alerts")
    assert excinfo.value.response.status_code == 404


def test_paginate_yields_nothing_for_a_bodiless_success(transport: FixtureTransport) -> None:
    assert list(transport.paginate("GET", "/repos/acme/web-app/vulnerability-alerts")) == []


def test_request_raw_re_encodes_a_file_fixture(transport: FixtureTransport) -> None:
    raw = transport.request_raw("GET", "/orgs/acme")
    assert raw.status_code == 200
    assert raw.json() == {"login": "acme"}


def test_request_raw_carries_the_status_of_a_bodiless_success(transport: FixtureTransport) -> None:
    raw = transport.request_raw("GET", "/repos/acme/web-app/vulnerability-alerts")
    assert (raw.status_code, raw.content) == (204, b"")
    assert raw.json() is None


def test_the_raw_helper_wraps_a_transport_that_only_implements_request() -> None:
    class _JsonOnly:
        def request(self, method: str, path: str, **kwargs: object) -> object:
            return {"ok": True}

        def paginate(self, method: str, path: str, **kwargs: object):
            yield self.request(method, path)

    raw = request_raw(_JsonOnly(), "GET", "/x")  # type: ignore[arg-type]
    assert raw.status_code == 200
    assert raw.headers == {}
    assert raw.json() == {"ok": True}
