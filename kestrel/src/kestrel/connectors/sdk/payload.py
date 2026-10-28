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

`classify_worker_type` turns a provider's free-text user type into the
`worker_type` vocabulary every connector shares, so a policy can ask for
"contractors" without knowing which tenant spells it `Contractor`,
`contingent`, or `CW`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

__all__ = ["classify_worker_type", "looks_like_email", "reduce_url_to_host", "sub_dict", "sub_list"]


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


# Whole words of a provider's user-type field, lowercased, that decide a
# ``worker_type``. Matched as tokens, never substrings: "Internal" must not
# read as "intern", "Template" as "temp", or "Rapid" as "api". Order matters:
# the first family with a hit wins, so "Contract Employee" reads as a
# contractor rather than staff.
_WORKER_TYPE_HINTS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "contractor",
        frozenset({"contractor", "contractors", "contract", "contingent", "temporary", "temp", "intern", "cw"}),
    ),
    (
        "vendor_or_partner",
        frozenset({"vendor", "vendors", "partner", "partners", "supplier", "consultant", "agency", "external"}),
    ),
    ("guest", frozenset({"guest", "guests", "visitor"})),
    ("service", frozenset({"service", "bot", "system", "integration", "api"})),
    (
        "employee",
        frozenset({"employee", "employees", "staff", "fte", "regular", "permanent", "internal"}),
    ),
)
_EMPLOYEE_PHRASES = ("full time", "full-time")
# "Non-Employee", "Not staff": the negation flips an employee label to
# "not an employee", which says nothing about which kind of non-employee.
_NEGATIONS = frozenset({"non", "not", "no"})


def classify_worker_type(user_type_raw: object, *, is_guest: bool = False, is_bot: bool = False) -> str:
    """The shared ``worker_type`` for a provider user-type field.

    ``is_bot`` and ``is_guest`` are the provider's own structural facts (a Slack
    bot, a GitHub outside collaborator) and win over any label. A blank or
    unrecognized label is ``unknown``: most tenants never fill the field in,
    and guessing ``employee`` would hide every contractor the operator has not
    yet mapped through a classification rule.
    """
    if is_bot:
        return "service"
    if is_guest:
        return "guest"
    if not isinstance(user_type_raw, str):
        return "unknown"
    label = user_type_raw.strip().lower()
    if not label:
        return "unknown"
    tokens = re.findall(r"[a-z0-9]+", label)
    negated = any(token in _NEGATIONS for token in tokens)
    words = set(tokens)
    for worker_type, hints in _WORKER_TYPE_HINTS:
        if words & hints:
            if worker_type == "employee" and negated:
                return "unknown"
            return worker_type
    if not negated and any(phrase in label for phrase in _EMPLOYEE_PHRASES):
        return "employee"
    return "unknown"


def looks_like_email(value: object) -> str | None:
    """``value`` lowercased when it is address-shaped, else ``None``.

    Provider "manager" fields are free text on some tenants (a display name or
    an employee number); only a real address is useful for correlating the
    manager to an account.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if "@" not in candidate or candidate.startswith("@") or candidate.endswith("@") or " " in candidate:
        return None
    local, _, domain = candidate.rpartition("@")
    if not local or "." not in domain:
        return None
    return candidate.lower()
