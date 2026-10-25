# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Concise, display-safe summaries of failed webhook deliveries.

A receiver behind a proxy often answers a failure with a full HTML error
page. Recording that verbatim put markup and inline CSS into the deliveries
table and into failure notifications. A delivery records instead the status
code plus a short excerpt of the body's text: tags (and the contents of
``<script>`` / ``<style>``) removed, entities decoded, whitespace collapsed,
capped at ``ERROR_EXCERPT_MAX_CHARS``.
"""

from __future__ import annotations

import html
import re

ERROR_EXCERPT_MAX_CHARS = 200

# Only the first part of a body is ever summarised; an error page that is
# megabytes long should not cost a full regex pass.
_SCAN_LIMIT = 20_000

_SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)
_TAGS = re.compile(r"<[^>]*>")
_WHITESPACE = re.compile(r"\s+")


def summarize_error_text(text: str | None, *, limit: int = ERROR_EXCERPT_MAX_CHARS) -> str:
    """Plain, single-line text from ``text`` (which may be HTML), at most
    ``limit`` characters with an ellipsis when cut."""
    if not text:
        return ""
    cleaned = text[:_SCAN_LIMIT]
    cleaned = _SCRIPT_STYLE.sub(" ", cleaned)
    cleaned = _COMMENTS.sub(" ", cleaned)
    cleaned = _TAGS.sub(" ", cleaned)
    cleaned = html.unescape(cleaned).replace("\xa0", " ")
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def summarize_http_failure(status_code: int, body: str | None) -> str:
    """``HTTP <status>: <excerpt>``, or ``HTTP <status>`` when the body has no text."""
    excerpt = summarize_error_text(body)
    return f"HTTP {status_code}: {excerpt}" if excerpt else f"HTTP {status_code}"


# Stored messages also include SSRF and transport errors, which run longer
# than a response excerpt; this bound is for display of any of them.
DISPLAY_ERROR_MAX_CHARS = 500


def display_delivery_error(message: str | None) -> str | None:
    """A stored ``error_message`` made safe to show (deliveries table,
    notifications). New rows are already summaries; rows recorded before
    summaries existed may still hold a raw HTML page."""
    return summarize_error_text(message, limit=DISPLAY_ERROR_MAX_CHARS) or None
