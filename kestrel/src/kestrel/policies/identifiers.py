# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy identifiers shared by compilation and filesystem export."""

from __future__ import annotations

import re

_POLICY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


def validate_policy_id(value: str) -> str:
    """Return a portable filename-safe identifier, or reject it."""
    if not _POLICY_ID.fullmatch(value):
        raise ValueError(
            "POLICY_ID must be 1–128 ASCII letters, digits, underscores or hyphens, starting with a letter or digit"
        )
    return value
