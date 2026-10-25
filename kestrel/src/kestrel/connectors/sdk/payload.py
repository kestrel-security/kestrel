# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Safe accessors for provider payloads.

Provider JSON is untrusted shape. A field that is an object on every tenant
the connector was written against can arrive as `null`, a string, or be absent
entirely -- a plan that does not include the feature, a permission the token
does not carry, or simply a schema the vendor changed. Reaching into it
directly is how a connector turns an unexpected payload into an
`AttributeError` mid-sync, which surfaces to the operator as a failed run
rather than as reduced coverage.

The idiom these replace reads the key twice and does not narrow for a type
checker:

    settings = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}

Use `sub_dict(payload, "settings")` instead: one lookup, an empty dict when the
field is missing or the wrong type, and a return type that chains safely.

`reduce_url_to_host` is for the other direction: removing a sensitive URL from
a payload before it is persisted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

__all__ = ["reduce_url_to_host", "sub_dict", "sub_list"]


def sub_dict(payload: Mapping[str, Any] | None, key: str) -> dict[str, Any]:
    """The nested object at `key`, or an empty dict if it is missing, null, or
    not an object. Chains: `sub_dict(sub_dict(p, "settings"), "oauthClient")`."""
    if payload is None:
        return {}
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def sub_list(payload: Mapping[str, Any] | None, key: str) -> list[Any]:
    """The nested array at `key`, or an empty list if it is missing, null, or
    not an array."""
    if payload is None:
        return []
    value = payload.get(key)
    return value if isinstance(value, list) else []


def reduce_url_to_host(payload: Mapping[str, Any], key: str) -> dict[str, Any]:
    """A copy of `payload` with the URL at `key` replaced by its host and scheme.

    Webhook and callout URLs often carry credentials in the path or query, and a
    connector's `raw_source` is persisted verbatim, so redact them at
    collection. `{key}_host` and `{key}_scheme` are added (None when the URL has
    no host or scheme) and `key` is removed. A missing, empty, or non-string
    value leaves the copy unchanged.
    """
    redacted = dict(payload)
    url = redacted.get(key)
    if isinstance(url, str) and url:
        parsed = urlsplit(url)
        redacted[f"{key}_host"] = parsed.netloc or None
        redacted[f"{key}_scheme"] = parsed.scheme or None
        redacted.pop(key, None)
    return redacted
