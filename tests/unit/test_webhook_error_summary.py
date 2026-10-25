# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""A failed webhook delivery records a concise error, not the receiver's raw
HTML error page: status code plus a short, tag-free, whitespace-collapsed
excerpt. That string is what the deliveries table and the failure
notification show."""

from __future__ import annotations

from kestrel.webhooks.errors import ERROR_EXCERPT_MAX_CHARS, summarize_error_text, summarize_http_failure

_NGINX_502 = """<!DOCTYPE html>
<html>
<head><title>502 Bad Gateway</title>
<style>body { font-family: sans-serif; }</style>
<script>var x = "<b>not text</b>";</script>
</head>
<body>
<center><h1>502   Bad
Gateway</h1></center>
<hr><center>nginx/1.25.3</center>
</body>
</html>
"""


def test_html_is_reduced_to_its_text():
    summary = summarize_http_failure(502, _NGINX_502)

    assert summary == "HTTP 502: 502 Bad Gateway 502 Bad Gateway nginx/1.25.3"
    assert "<" not in summary
    assert "font-family" not in summary
    assert "not text" not in summary


def test_plain_text_body_is_kept():
    assert summarize_http_failure(500, "upstream exploded") == "HTTP 500: upstream exploded"


def test_empty_body_is_just_the_status():
    assert summarize_http_failure(503, "") == "HTTP 503"
    assert summarize_http_failure(503, "  <html><body> </body></html> ") == "HTTP 503"


def test_long_bodies_are_capped():
    summary = summarize_http_failure(500, "<p>" + "word " * 500 + "</p>")

    excerpt = summary.removeprefix("HTTP 500: ")
    assert len(excerpt) <= ERROR_EXCERPT_MAX_CHARS
    assert excerpt.endswith("…")


def test_entities_are_decoded():
    assert summarize_error_text("Service&nbsp;Unavailable &amp; retrying") == "Service Unavailable & retrying"
