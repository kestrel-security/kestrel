# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""SaaS activity event ingestion, retention, and reporting."""

from kestrel.activity.retention import (
    DEFAULT_MAX_EVENTS_PER_INSTANCE,
    DEFAULT_RETENTION_DAYS,
    prune_activity_events,
)

__all__ = [
    "DEFAULT_MAX_EVENTS_PER_INSTANCE",
    "DEFAULT_RETENTION_DAYS",
    "prune_activity_events",
]
