# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Parse Changes command-bar tokens.

Tokens mirror Findings search lightly: ``class:``, ``significance:``, ``app:``,
``person:``. Remaining text is free-text search. Parsed server-side so the API
and chip UI agree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TOKEN_RE = re.compile(r'\w+:"[^"]*"|\w+:\S+|"[^"]*"|\S+')


@dataclass(frozen=True)
class ParsedChangeSearch:
    free_text: str | None = None
    person: str | None = None
    change_classes: tuple[str, ...] = ()
    min_significance: str | None = None
    app: str | None = None


def tokenize(raw: str) -> list[str]:
    return _TOKEN_RE.findall(raw.strip())


def parse_change_search(raw: str | None) -> ParsedChangeSearch:
    if not raw or not raw.strip():
        return ParsedChangeSearch()

    free: list[str] = []
    person: str | None = None
    classes: list[str] = []
    significance: str | None = None
    app: str | None = None

    for token in tokenize(raw):
        colon = token.find(":")
        if colon <= 0:
            free.append(token)
            continue
        key = token[:colon].lower()
        value = token[colon + 1 :].strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        if not value:
            free.append(token)
            continue
        if key in {"class", "change_class"}:
            classes.append(value)
            continue
        if key in {"significance", "min_significance"} and value.lower() in {
            "high",
            "medium",
            "low",
        }:
            significance = value.lower()
            continue
        if key in {"person", "identity", "user"}:
            person = value
            continue
        if key in {"app", "application"}:
            app = value
            continue
        free.append(token)

    free_text = " ".join(free).strip() or None
    return ParsedChangeSearch(
        free_text=free_text,
        person=person,
        change_classes=tuple(classes),
        min_significance=significance,
        app=app,
    )
