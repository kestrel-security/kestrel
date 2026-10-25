# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Opaque bearer tokens (not JWT): revocation, session listing, and lockout
all require a DB hit anyway, so JWT's stateless benefit doesn't apply, and
it would add signing-key lifecycle risk for nothing. Tokens are generated
with secrets.token_urlsafe and only ever stored as a SHA-256 hash -- a DB
dump alone yields no usable credential."""

from __future__ import annotations

import hashlib
import secrets

TOKEN_ENTROPY_BYTES = 32


def generate_token(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)}"


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
