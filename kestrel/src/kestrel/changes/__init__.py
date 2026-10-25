# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Change detection reads over the sync diff."""

from kestrel.changes.classify import (
    ChangeClass,
    ClassifiedChange,
    Significance,
    classify_event,
    classify_events,
)
from kestrel.changes.feed import ChangeFeedError, change_feed, resolve_connector_instance
from kestrel.changes.labels import entity_label
from kestrel.changes.query import ParsedChangeSearch, parse_change_search

__all__ = [
    "ChangeClass",
    "ChangeFeedError",
    "ClassifiedChange",
    "ParsedChangeSearch",
    "Significance",
    "change_feed",
    "classify_event",
    "classify_events",
    "entity_label",
    "parse_change_search",
    "resolve_connector_instance",
]
