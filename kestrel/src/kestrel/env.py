# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Environment variable helpers for ``KESTREL_*`` configuration."""

from __future__ import annotations

import os


def getenv(name: str, default: str | None = None) -> str | None:
    """Read ``name`` from the environment, or return ``default`` when unset/empty."""
    raw = os.environ.get(name)
    if raw is not None and raw != "":
        return raw
    return default


def getenv_str(name: str, default: str = "") -> str:
    value = getenv(name)
    if value is None:
        return default
    return value


def getenv_bool(name: str, default: bool) -> bool:
    raw = getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def getenv_int(name: str, default: int) -> int:
    raw = getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)
