# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Stable local-development operator credentials.

Used by `kestrel init` / `kestrel demo up` / `make seed` so redeploys keep the same
login. These are **local/dev only** — never use them in production.
"""

from __future__ import annotations

# Documented in docs/getting-started.md, README.md,
# and .env.example. Keep all of those in sync when changing these values.
DEFAULT_DEV_ADMIN_EMAIL = "admin@kestrel.local"
DEFAULT_DEV_ADMIN_PASSWORD = "kestrel-dev-password"
