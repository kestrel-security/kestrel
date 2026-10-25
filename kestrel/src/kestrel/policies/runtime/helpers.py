# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers injected into every policy's sandbox namespace.

Policies cannot import, so before this module each pack carried its own copy
of the same few functions (``within_last_days`` alone was pasted into 28
files). The names in ``POLICY_HELPERS`` are available to every policy as
globals, in both runtimes and in ``kestrel policy test`` / dry run, because
all of them compile through ``RestrictedPythonRuntime.compile``.

Error semantics
---------------
A helper never turns data it cannot read into an answer. *Missing* data
(``None`` or an empty string) is reported as missing -- ``parse_timestamp``
and ``days_since`` return ``None`` and ``within_last_days`` returns ``False``
("not shown to be recent") -- and the policy decides what absence means.
*Malformed* data (a timestamp in a format nothing here recognizes) raises
``PolicyDataError``.

Raising is deliberate. ``policy()`` returns a bool per row, so a helper that
guessed would have to pick compliant or non-compliant on the author's behalf,
and whichever it picks is wrong for half of all call sites: "unparseable means
recent" hides a dormant account, "unparseable means old" hides a fresh audit
event. An exception instead fails the policy's evaluation: the
``PolicyEvaluation`` row is recorded with ``status = error`` and an
``error_message`` naming the policy, the subject, and the value, and no
findings are opened or auto-resolved for that policy in that run. A visible
evaluation error is preferable to silently wrong coverage in a security tool.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Any

SECONDS_PER_DAY = 86400.0


class PolicyDataError(ValueError):
    """A row holds a value a policy helper cannot interpret."""


def _describe(value: Any) -> str:
    text = repr(value)
    if len(text) > 80:
        text = text[:77] + "..."
    return f"{text} ({type(value).__name__})"


def parse_timestamp(value: Any) -> datetime | None:
    """Return ``value`` as a timezone-aware UTC datetime, or ``None`` if missing.

    Accepts a ``datetime`` (naive values are taken as UTC, which is how every
    connector stores them), a ``date`` (midnight UTC), an int/float Unix epoch
    in seconds, or an ISO 8601 string (``Z`` suffix allowed; a numeric string
    is not read as an epoch, since ``"20240101"`` is a valid ISO date). ``None``
    and blank strings are missing and return
    ``None``. Anything else raises ``PolicyDataError``; see the module
    docstring for why this does not fall back to a guess.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, bool):
        raise PolicyDataError(f"expected a timestamp, got {_describe(value)}")
    if isinstance(value, (int, float)):
        return _from_epoch(value, value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            raise PolicyDataError(f"unparseable timestamp {_describe(value)}") from None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    raise PolicyDataError(f"expected a timestamp, got {_describe(value)}")


def _from_epoch(seconds: float, original: Any) -> datetime:
    if not math.isfinite(seconds):
        raise PolicyDataError(f"unparseable timestamp {_describe(original)}")
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise PolicyDataError(f"timestamp out of range {_describe(original)}") from None


def days_since(value: Any) -> float | None:
    """Days elapsed since ``value``, or ``None`` if it is missing.

    Negative for a timestamp in the future. Raises ``PolicyDataError`` for a
    malformed timestamp (see ``parse_timestamp``).
    """
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return (time.time() - parsed.timestamp()) / SECONDS_PER_DAY


def within_last_days(value: Any, days: float) -> bool:
    """True when ``value`` is a timestamp no more than ``days`` days ago.

    A missing timestamp returns ``False``: nothing shows it is recent. That
    makes the dormancy idiom ``return within_last_days(last_active, 90)``
    report an account with no recorded activity, and the audit-event idiom
    ``if not within_last_days(occurred, 30): return True`` skip an event with no
    time. A policy that wants the other reading checks for ``None`` first. A
    malformed timestamp raises ``PolicyDataError`` rather than guessing.
    A future timestamp counts as recent.
    """
    elapsed = days_since(value)
    if elapsed is None:
        return False
    return elapsed <= days


def has_admin_grant(resource: dict[str, Any]) -> bool:
    """True when any grant attached under ``resource["_related"]["grants"]``
    carries ``permission_level == "admin"``.

    The runtime attaches related grants to ``identity`` rows only; on any other
    resource type, or when there are none, this is ``False``.
    """
    related = resource.get("_related") or {}
    for item in related.get("grants") or []:
        grant = item.get("grant") or {}
        if grant.get("permission_level") == "admin":
            return True
    return False


def application_matches(
    resource: dict[str, Any],
    types: Iterable[str] = (),
    name_contains: str | None = None,
) -> bool:
    """True when the row's ``application`` has one of ``types``, or its name
    contains ``name_contains`` (case-insensitive).

    For connectors whose catalog type is not unique (a custom connector built
    from a template), matching on name is the only way to scope a policy.
    """
    application = resource.get("application") or {}
    if application.get("type") in set(types):
        return True
    if name_contains:
        return name_contains.casefold() in str(application.get("name") or "").casefold()
    return False


# Every name injected into the policy namespace. Adding a helper here makes it
# part of the authoring contract: document it in docs/policies.md and keep it
# pure (no I/O, no access to anything outside the row it is handed).
POLICY_HELPERS: dict[str, Any] = {
    "PolicyDataError": PolicyDataError,
    "parse_timestamp": parse_timestamp,
    "days_since": days_since,
    "within_last_days": within_last_days,
    "has_admin_grant": has_admin_grant,
    "application_matches": application_matches,
}
