# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the SDK's credential helpers and payload URL redaction."""

from __future__ import annotations

from typing import Any

import pytest
from kestrel.connectors.sdk.credentials import bearer_headers, first_secret, normalize_pem
from kestrel.connectors.sdk.payload import reduce_url_to_host

# -- first_secret ---------------------------------------------------------


def test_first_secret_returns_the_first_non_empty_name_in_order() -> None:
    secrets = {"token": "legacy", "api_token": "current"}
    assert first_secret(secrets, "api_token", "token") == "current"
    assert first_secret(secrets, "token", "api_token") == "legacy"


def test_first_secret_skips_empty_values() -> None:
    assert first_secret({"api_token": "", "token": "t"}, "api_token", "token") == "t"


def test_first_secret_is_none_when_nothing_is_set() -> None:
    assert first_secret({"api_token": ""}, "api_token", "token") is None
    assert first_secret({}, "api_token") is None


def test_first_secret_does_not_strip() -> None:
    assert first_secret({"token": " t "}, "token") == " t "


# -- bearer_headers -------------------------------------------------------


def test_bearer_headers() -> None:
    assert bearer_headers("abc") == {"Authorization": "Bearer abc", "Accept": "application/json"}


# -- normalize_pem --------------------------------------------------------


def test_normalize_pem_unescapes_newlines_in_a_pem() -> None:
    raw = "  -----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\\n  "
    assert normalize_pem(raw) == "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"


def test_normalize_pem_leaves_a_real_pem_alone() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
    assert normalize_pem(pem) == pem


def test_normalize_pem_only_rewrites_pem_shaped_values() -> None:
    assert normalize_pem(" not\\na key ") == "not\\na key"


# -- reduce_url_to_host ---------------------------------------------------


def test_reduce_url_to_host_replaces_the_url_with_host_and_scheme() -> None:
    config = {"url": "https://user:pw@hooks.example.com/path?token=secret", "content_type": "json"}

    redacted = reduce_url_to_host(config, "url")

    assert redacted == {
        "content_type": "json",
        "url_host": "user:pw@hooks.example.com",
        "url_scheme": "https",
    }
    assert config["url"].startswith("https://"), "the input must not be mutated"


def test_reduce_url_to_host_uses_none_for_a_missing_host() -> None:
    assert reduce_url_to_host({"uri": "relative/path"}, "uri") == {"uri_host": None, "uri_scheme": None}


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": None}, {"url": 5}])
def test_reduce_url_to_host_leaves_non_urls_unchanged(payload: dict[str, Any]) -> None:
    redacted = reduce_url_to_host(payload, "url")
    assert redacted == payload
    assert redacted is not payload


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("Contractor", "contractor"),
        ("Contract Employee", "contractor"),
        ("contingent worker", "contractor"),
        ("CW", "contractor"),
        ("Intern", "contractor"),
        ("Vendor", "vendor_or_partner"),
        ("Employee", "employee"),
        ("FTE", "employee"),
        ("Full-Time", "employee"),
        ("Internal", "employee"),
        ("Internal Employee", "employee"),
        # Substrings must not decide: these used to read as contractor/service.
        ("Template", "unknown"),
        ("Rapid", "unknown"),
        ("Systematic", "unknown"),
        # A negated employee label says only "not an employee".
        ("Non-Employee", "unknown"),
        ("Not staff", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_worker_type_matches_whole_words(label, expected):
    from kestrel.connectors.sdk.payload import classify_worker_type

    assert classify_worker_type(label) == expected


def test_classify_worker_type_structural_facts_win():
    from kestrel.connectors.sdk.payload import classify_worker_type

    assert classify_worker_type("Employee", is_bot=True) == "service"
    assert classify_worker_type("Employee", is_guest=True) == "guest"
