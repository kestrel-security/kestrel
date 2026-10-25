# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Webhook endpoint URLs must be https: deliveries carry an HMAC-signed
payload, so plain http would put it on the wire in cleartext. Hosts on
`KESTREL_CONNECTOR_URL_ALLOWLIST` (local labs) are the only exception.
URLs are IP literals so the SSRF guard never resolves DNS."""

from __future__ import annotations

import pytest
from kestrel.webhooks.authoring import WebhookAuthoringError, validate_endpoint_url

pytestmark = pytest.mark.unit


def test_https_public_endpoint_is_accepted(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    assert validate_endpoint_url(" https://93.184.216.34/hook ") == "https://93.184.216.34/hook"


def test_plain_http_public_endpoint_is_rejected(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    with pytest.raises(WebhookAuthoringError, match="https"):
        validate_endpoint_url("http://93.184.216.34/hook")


def test_plain_http_is_allowed_for_an_allowlisted_lab_host(monkeypatch):
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "127.0.0.1")
    assert validate_endpoint_url("http://127.0.0.1:9000/hook") == "http://127.0.0.1:9000/hook"


def test_unsupported_scheme_is_rejected(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    with pytest.raises(WebhookAuthoringError):
        validate_endpoint_url("ftp://93.184.216.34/hook")
