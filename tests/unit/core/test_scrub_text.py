# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""``kestrel.secrets.scrub.scrub_text`` -- what may reach run history and API errors."""

from __future__ import annotations

from kestrel.secrets.scrub import scrub_text
from kestrel.secrets.store import REDACTED_PLACEHOLDER


def test_known_secret_values_are_replaced():
    out = scrub_text("401 for token s3cr3t-value in request", ["s3cr3t-value"])
    assert "s3cr3t-value" not in out
    assert REDACTED_PLACEHOLDER in out


def test_url_query_strings_are_dropped():
    out = scrub_text("GET https://api.example.test/v1/users?access_token=abc123&x=1 failed")
    assert "access_token=abc123" not in out
    assert "https://api.example.test/v1/users?" in out


def test_bearer_and_provider_token_shapes_are_masked():
    text = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123 and xoxb-1234567890-abcdef"
    out = scrub_text(text)
    assert "ghp_" not in out
    assert "xoxb-" not in out


def test_output_is_bounded():
    assert len(scrub_text("x" * 5000)) == 2000


def test_plain_messages_pass_through():
    assert scrub_text("Connector instance not found") == "Connector instance not found"
