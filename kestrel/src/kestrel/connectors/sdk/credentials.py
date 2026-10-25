# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Small helpers for turning connector secrets into request credentials.

Which secrets a connector accepts, in what order of preference, and which
headers its API expects stay in the connector's own ``auth.py``. These cover
the parts every connector repeats.
"""

from __future__ import annotations

from collections.abc import Mapping

__all__ = ["bearer_headers", "first_secret", "normalize_pem"]


def first_secret(secrets: Mapping[str, str], *names: str) -> str | None:
    """The first non-empty secret among ``names``, in order, or None.

    Values are returned as stored (not stripped), so accepting a legacy field
    name alongside the current one is ``first_secret(secrets, "api_token", "token")``.
    """
    for name in names:
        value = secrets.get(name)
        if value:
            return value
    return None


def bearer_headers(token: str) -> dict[str, str]:
    """``Authorization: Bearer <token>`` plus ``Accept: application/json``."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def normalize_pem(private_key: str) -> str:
    """A PEM private key with surrounding whitespace removed and literal ``\\n``
    escapes turned into newlines.

    Keys pasted into a single-line form field, or copied out of a JSON string,
    arrive with the two characters ``\\`` ``n`` where line breaks belong, which
    a PEM parser rejects. Only a value that looks like PEM (contains
    ``-----BEGIN``) is rewritten.
    """
    cleaned = private_key.strip()
    if "\\n" in cleaned and "-----BEGIN" in cleaned:
        cleaned = cleaned.replace("\\n", "\n")
    return cleaned
