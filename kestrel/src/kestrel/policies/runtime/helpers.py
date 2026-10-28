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

import contextlib
import contextvars
import fnmatch
import ipaddress
import math
import re
import time
import types
from collections.abc import Iterable, Iterator
from datetime import UTC, date, datetime
from typing import Any

from kestrel.policies.vocabulary import (
    ACTIVITY_REPORTING_APPLICATION_TYPES,
    IDP_APPLICATION_TYPES,
    PRIVILEGED_ROLE_HINTS,
    TRUSTED_ACTIVITY_SOURCES,
)

SECONDS_PER_DAY = 86400.0

__all__ = [
    "IDP_APPLICATION_TYPES",
    "POLICY_HELPERS",
    "POLICY_TIME",
    "PRIVILEGED_ROLE_HINTS",
    "TRUSTED_ACTIVITY_SOURCES",
    "PolicyDataError",
    "pinned_now",
]


class PolicyDataError(ValueError):
    """A row holds a value a policy helper cannot interpret."""


# One evaluation run reads one clock: every row (and every helper call on it)
# sees the same "now", and a test can freeze it. Unset means the wall clock.
_PINNED_NOW: contextvars.ContextVar[float | None] = contextvars.ContextVar("kestrel_policy_now", default=None)


def now_seconds() -> float:
    """The evaluation clock as a Unix time: pinned for the run, else wall time."""
    pinned = _PINNED_NOW.get()
    return time.time() if pinned is None else pinned


@contextlib.contextmanager
def pinned_now(at: float | None = None) -> Iterator[float]:
    """Fix ``now()`` (and ``days_since`` / ``within_last_days``) for a block.

    The runtimes wrap each evaluation pass in this so a pass over thousands of
    rows judges them all against one instant; tests pass ``at`` to freeze it.
    Not exposed to policies.
    """
    value = time.time() if at is None else float(at)
    token = _PINNED_NOW.set(value)
    try:
        yield value
    finally:
        _PINNED_NOW.reset(token)


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


def now() -> datetime:
    """The current time as a timezone-aware UTC datetime.

    Fixed for the whole evaluation run, so every row is judged against the
    same instant. Compare it only with values from ``parse_timestamp``.
    """
    return datetime.fromtimestamp(now_seconds(), tz=UTC)


def days_since(value: Any) -> float | None:
    """Days elapsed since ``value``, or ``None`` if it is missing.

    Negative for a timestamp in the future. Raises ``PolicyDataError`` for a
    malformed timestamp (see ``parse_timestamp``).
    """
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return (now_seconds() - parsed.timestamp()) / SECONDS_PER_DAY


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


_DURATION_NUMBER = r"(\d+(?:\.\d+)?)"
_ISO_DURATION_RE = re.compile(
    rf"^P(?:{_DURATION_NUMBER}W)?(?:{_DURATION_NUMBER}D)?"
    rf"(?:T(?:{_DURATION_NUMBER}H)?(?:{_DURATION_NUMBER}M)?(?:{_DURATION_NUMBER}S)?)?$"
)
_ISO_DURATION_UNITS = (7 * SECONDS_PER_DAY, SECONDS_PER_DAY, 3600.0, 60.0, 1.0)
_PROTOBUF_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)s$")


def duration_seconds(value: Any) -> float | None:
    """Seconds in a duration string, or ``None`` if it is missing.

    Accepts ISO 8601 durations in weeks, days, hours, minutes and seconds
    (``P30D``, ``PT12H``, ``PT90M``, ``P1DT6H``) and protobuf-JSON durations
    (``"86400s"``). Years and months have no fixed length and raise
    ``PolicyDataError``, as does a bare number: its unit is unknown, so
    convert it explicitly (``minutes * 60``).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyDataError(f"expected a duration string, got {_describe(value)}")
    text = value.strip()
    if not text:
        return None
    protobuf = _PROTOBUF_DURATION_RE.match(text)
    if protobuf:
        return float(protobuf.group(1))
    iso = _ISO_DURATION_RE.match(text.upper())
    if iso is None or text.upper().endswith("T") or not any(iso.groups()):
        raise PolicyDataError(f"unparseable duration {_describe(value)}")
    return sum(float(part) * unit for part, unit in zip(iso.groups(), _ISO_DURATION_UNITS, strict=True) if part)


def get_path(value: Any, path: str, default: Any = None) -> Any:
    """``value["a"]["b"]["c"]`` for ``path="a.b.c"``, or ``default`` when any
    step is missing, ``None``, or not a dict.

    Saves the ``(row.get("a") or {}).get("b")`` chains that raise
    AttributeError the first time a connector leaves a field out.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("get_path() needs a non-empty dotted path")
    current = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
    return default if current is None else current


def email_domain(value: Any) -> str | None:
    """The lowercased domain of an email address, or ``None`` if missing.

    A value with no ``@``, or nothing on either side of it, raises
    ``PolicyDataError``: guessing a domain would misjudge who is external.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyDataError(f"expected an email address, got {_describe(value)}")
    text = value.strip()
    if not text:
        return None
    local, sep, domain = text.rpartition("@")
    domain = domain.strip().rstrip(".")
    if not sep or not local or not domain:
        raise PolicyDataError(f"not an email address {_describe(value)}")
    return domain.casefold()


def _as_tuple(values: str | Iterable[str]) -> tuple[str, ...]:
    # A bare string would otherwise be iterated one character at a time.
    return (values,) if isinstance(values, str) else tuple(values)


def domain_matches(value: Any, domains: str | Iterable[str]) -> bool:
    """True when ``value`` (an email address or a host name) is in one of
    ``domains`` or a subdomain of it, case-insensitive.

    ``domain_matches("ana@eu.acme.com", ["acme.com"])`` is True. A missing
    value returns ``False``; a malformed email raises ``PolicyDataError``.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return False
    if not isinstance(value, str):
        raise PolicyDataError(f"expected an email address or domain, got {_describe(value)}")
    domain = (email_domain(value) or "") if "@" in value else value.strip().rstrip(".").casefold()
    for candidate in _as_tuple(domains):
        wanted = candidate.strip().strip(".").casefold()
        if wanted and (domain == wanted or domain.endswith("." + wanted)):
            return True
    return False


def ip_in_networks(value: Any, networks: str | Iterable[str]) -> bool:
    """True when the IP address ``value`` falls inside any of ``networks``
    (CIDR strings such as ``"10.0.0.0/8"`` or ``"2001:db8::/32"``).

    A missing address returns ``False`` (not shown to be inside); a malformed
    address or network raises ``PolicyDataError``. An IPv4 address is never
    inside an IPv6 network, and the reverse.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return False
    if not isinstance(value, str):
        raise PolicyDataError(f"expected an IP address string, got {_describe(value)}")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise PolicyDataError(f"not an IP address {_describe(value)}") from None
    for network in _as_tuple(networks):
        try:
            parsed = ipaddress.ip_network(str(network).strip(), strict=False)
        except ValueError:
            raise PolicyDataError(f"not a network {_describe(network)}") from None
        if address.version == parsed.version and address in parsed:
            return True
    return False


def matches_any(value: Any, patterns: str | Iterable[str]) -> bool:
    """True when ``value`` matches any shell-style glob in ``patterns``
    (``*``, ``?``, ``[abc]``), case-insensitive.

    For scoping by name: ``matches_any(repo["name"], ["prod-*", "*-secrets"])``.
    A missing value returns ``False``; a non-string raises ``PolicyDataError``.
    """
    if value is None:
        return False
    if not isinstance(value, str):
        raise PolicyDataError(f"expected a string, got {_describe(value)}")
    text = value.casefold()
    return any(fnmatch.fnmatchcase(text, pattern.casefold()) for pattern in _as_tuple(patterns))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def trusted_last_active(value: Any) -> Any:
    """The ``last_active_at`` of an identity row, its ``identity`` dict, or a
    cluster account, or ``None`` when its ``last_active_source`` is not real
    activity.

    ``login``, ``audit`` and ``analytics`` record something the account did;
    ``profile`` is when the profile last changed and says nothing about use.
    A dict with a timestamp and no source at all (a hand-written fixture) is
    taken at face value. Pass the result to ``within_last_days`` or
    ``days_since``; use ``activity_status`` when "no trusted source" must be
    told apart from "never active".
    """
    data = _as_dict(value)
    if "identity" in data:
        data = _as_dict(data.get("identity"))
    source = data.get("last_active_source")
    if source is not None and source not in TRUSTED_ACTIVITY_SOURCES:
        return None
    timestamp = data.get("last_active_at")
    return None if timestamp in (None, "") else timestamp


def activity_status(value: Any, days: float) -> str:
    """``"active"``, ``"stale"``, ``"never"`` or ``"unknown"`` for a whole
    identity row, its ``identity`` dict, or a cluster account against a window
    of ``days``.

    ``unknown`` means the account cannot be judged: its only timestamp comes
    from an untrusted source (a profile-modified time), or its application
    does not report a sign-in per account (GitHub's audit log sees only
    administrative actions; a custom connector may collect no activity at
    all) and recorded none. ``never`` means the provider does report sign-ins
    (Okta, Google Workspace, Slack) and has none for this account. A dormancy
    policy normally treats ``unknown`` as compliant (not assessable) and
    ``never`` like ``stale``. A malformed timestamp raises ``PolicyDataError``.
    """
    data = _as_dict(value)
    application_type = data.get("application_type")
    if "identity" in data:
        application_type = _as_dict(data.get("application")).get("type")
        data = _as_dict(data.get("identity"))
    source = data.get("last_active_source")
    if source is not None and source not in TRUSTED_ACTIVITY_SOURCES:
        return "unknown"
    timestamp = data.get("last_active_at")
    if timestamp in (None, ""):
        # "never" only where the application would have reported a sign-in.
        # A dict with no application at all (a hand-written check) is taken
        # at its word.
        if application_type is None or application_type in ACTIVITY_REPORTING_APPLICATION_TYPES:
            return "never"
        return "unknown"
    return "active" if within_last_days(timestamp, days) else "stale"


def cluster_accounts(
    resource: dict[str, Any],
    application_types: str | Iterable[str] | None = None,
    include_self: bool = True,
    active_only: bool = False,
) -> list[dict[str, Any]]:
    """The same person's accounts across applications, from
    ``resource["cluster"]["accounts"]``, filtered.

    ``application_types`` keeps accounts in those application types only;
    ``include_self=False`` drops this row's own account; ``active_only``
    drops disabled accounts. Rows without a cluster yield ``[]``. Each
    account carries ``application_type``, ``is_disabled``, ``mfa_enabled``,
    ``worker_type``, ``roles``, ``privileged``, ``last_active_at`` and
    ``last_active_source``, among others.
    """
    cluster = _as_dict(resource.get("cluster"))
    accounts = [account for account in (cluster.get("accounts") or []) if isinstance(account, dict)]
    if not include_self:
        self_id = str(resource.get("_subject_id") or "")
        accounts = [account for account in accounts if str(account.get("identity_id") or "") != self_id]
    if application_types is not None:
        wanted = set(_as_tuple(application_types))
        accounts = [account for account in accounts if account.get("application_type") in wanted]
    if active_only:
        accounts = [account for account in accounts if not account.get("is_disabled")]
    return accounts


def is_representative(resource: dict[str, Any]) -> bool:
    """True when this row is the account that should carry a one-per-person
    finding: the cluster's representative, or any row that has no cluster.

    Identity rows are one per account, so a check about the *person* (admin in
    two applications, dormant everywhere) would otherwise open one finding
    per account. Gate it with ``if not is_representative(resource): return True``.
    """
    cluster = _as_dict(resource.get("cluster"))
    representative = cluster.get("representative_identity_id")
    if not representative:
        return True
    return str(resource.get("_subject_id") or "") == str(representative)


def worker_type_of(resource: dict[str, Any]) -> str:
    """The person's worker type: ``employee``, ``contractor``,
    ``vendor_or_partner``, ``guest``, ``service`` or ``unknown``.

    Reads the cluster-level value (the identity provider's account wins over
    an application's guest flag), then this account's own. ``unknown`` is a
    real answer, from a provider that records no employment type and no
    operator classification rule matching; a policy must decide what it
    means and say so, usually "not shown to be a contractor".
    """
    cluster_value = _as_dict(resource.get("cluster")).get("worker_type")
    if cluster_value and cluster_value != "unknown":
        return str(cluster_value)
    own = _as_dict(resource.get("identity")).get("worker_type")
    return str(own) if own else "unknown"


def has_privileged_role(value: dict[str, Any]) -> bool:
    """True when an identity row or a cluster account holds a privileged role.

    A cluster account carries ``privileged`` directly; a row is judged by its
    ``roles`` names against the shared hints (admin, owner, super_admin, ...).
    """
    data = _as_dict(value)
    flagged = data.get("privileged")
    if flagged is not None:
        return bool(flagged)
    for role in data.get("roles") or []:
        name = str(role.get("name") if isinstance(role, dict) else role or "").lower()
        if name and any(hint in name for hint in PRIVILEGED_ROLE_HINTS):
            return True
    return False


def in_group(resource: dict[str, Any], patterns: str | Iterable[str]) -> bool:
    """True when one of the row's ``groups`` names matches a shell-style glob
    in ``patterns`` (case-insensitive).

    ``groups`` lists the group names this account is a member of in its own
    application; Google Workspace org units appear there too.
    """
    return any(matches_any(name, patterns) for name in resource.get("groups") or [] if isinstance(name, str))


def idp_account(resource: dict[str, Any]) -> dict[str, Any] | None:
    """The person's identity-provider account (Okta, Google Workspace) from the
    cluster, preferring an enabled one, or ``None`` when they have none.

    Its ``is_disabled``, ``mfa_enabled``, ``disabled_at`` and ``worker_type``
    are the facts offboarding and MFA policies compare the other accounts to.
    """
    candidates = [
        account for account in cluster_accounts(resource) if account.get("application_type") in IDP_APPLICATION_TYPES
    ]
    if not candidates:
        return None
    for account in candidates:
        if not account.get("is_disabled"):
            return account
    return candidates[0]


# Every name injected into the policy namespace. Adding a helper here makes it
# part of the authoring contract: document it in docs/policies.md and keep it
# pure (no I/O, no access to anything outside the row it is handed).
POLICY_HELPERS: dict[str, Any] = {
    "PolicyDataError": PolicyDataError,
    "now": now,
    "parse_timestamp": parse_timestamp,
    "days_since": days_since,
    "within_last_days": within_last_days,
    "duration_seconds": duration_seconds,
    "get_path": get_path,
    "has_admin_grant": has_admin_grant,
    "application_matches": application_matches,
    "email_domain": email_domain,
    "domain_matches": domain_matches,
    "ip_in_networks": ip_in_networks,
    "matches_any": matches_any,
    "trusted_last_active": trusted_last_active,
    "activity_status": activity_status,
    "cluster_accounts": cluster_accounts,
    "is_representative": is_representative,
    "worker_type_of": worker_type_of,
    "has_privileged_role": has_privileged_role,
    "in_group": in_group,
    "idp_account": idp_account,
}

# The sandbox's ``time``: the pure clock and formatting functions only, with
# ``time()`` / ``time_ns()`` reading the pinned evaluation clock. ``sleep``,
# ``tzset`` and the process / thread clocks are left out: a policy has no use
# for them, and the in-process runtime has no timeout to bound a sleep.
_POLICY_TIME_PASSTHROUGH = (
    "gmtime",
    "localtime",
    "mktime",
    "strftime",
    "strptime",
    "asctime",
    "ctime",
    "struct_time",
    "timezone",
    "altzone",
    "daylight",
    "tzname",
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
)


def _now_ns() -> int:
    return int(now_seconds() * 1_000_000_000)


def _policy_time_module() -> types.ModuleType:
    module = types.ModuleType("time", "The policy sandbox's subset of the time module.")
    for name in _POLICY_TIME_PASSTHROUGH:
        setattr(module, name, getattr(time, name))
    module.time = now_seconds  # type: ignore[attr-defined]
    module.time_ns = _now_ns  # type: ignore[attr-defined]
    return module


POLICY_TIME = _policy_time_module()
