# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Scrub free-form error text before it is persisted or returned.

Exception messages are the one place secrets leak by accident: an httpx
error repeats the request URL (query strings can carry tokens), an OAuth
exchange failure echoes the assertion, a misconfigured header shows up
verbatim. ``scrub_text`` removes every value it is told is a secret, every
bearer/token-shaped credential it can recognise, and every URL query string,
so ``ConnectorRun.error_summary`` and API error details are safe to show.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from kestrel.secrets.store import REDACTED_PLACEHOLDER

_BEARER_RE = re.compile(r"(?i)\b(bearer|token|ssws)\s+[A-Za-z0-9._~+/=-]{8,}")
_QUERY_RE = re.compile(r"(https?://[^\s?'\"]+)\?[^\s'\"]*")
# Well-known credential shapes: GitHub tokens, Slack tokens, Google OAuth, JWTs.
_TOKEN_SHAPES = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpe]-[A-Za-z0-9-]{10,}"
    r"|ya29\.[A-Za-z0-9._-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"
)
_MAX_LEN = 2000


def scrub_text(text: str, secret_values: Iterable[str] | None = None, *, max_len: int = _MAX_LEN) -> str:
    """Return ``text`` with secrets, credential shapes, and URL queries removed."""
    out = text or ""
    for value in secret_values or ():
        if isinstance(value, str) and len(value.strip()) >= 4:
            out = out.replace(value, REDACTED_PLACEHOLDER)
    out = _QUERY_RE.sub(lambda m: f"{m.group(1)}?{REDACTED_PLACEHOLDER}", out)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED_PLACEHOLDER}", out)
    out = _TOKEN_SHAPES.sub(REDACTED_PLACEHOLDER, out)
    return out[:max_len]
