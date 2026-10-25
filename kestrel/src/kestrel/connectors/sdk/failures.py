# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Classify connector failures: skip a gated family, or fail the sync.

Every connector answers the same three questions about an exception raised
while talking to its provider:

* **Is it a rate limit?** Provider-specific. Okta throttles with a plain 429;
  GitHub also throttles with a 403 carrying ``x-ratelimit-remaining: 0``;
  Google with a 403 whose body says ``rateLimitExceeded``. Each connector
  writes its own ``is_rate_limit`` predicate and passes it to the helpers here.
* **Is it skippable?** A permission or plan gate on one object family (403 or
  404) is recorded in ``skipped_object_types`` and the rest of the sync
  continues. A rate limit is *never* skippable: dropping a family because the
  token was throttled reports an incomplete inventory as complete, and
  deletion detection then reads the missing rows as mass revocation.
* **What class of failure is it?** A coarse, operator-facing label --
  ``authentication``, ``permission``, ``rate_limit``, ``http_<status>``,
  ``network`` or ``unknown`` -- used in health-check messages and in
  ``skipped_object_types``.

Health checks then turn ``{probe label: failure class}`` into one message with
`summarize_probe_failures`, which applies the same precedence for every
provider (authentication, then permission, then rate limit, then network) and
takes the wording from a per-connector `FailureMessages`.

The helpers duck-type the exception (``exc.response.status_code``,
``exc.response.headers``), so they work with ``httpx.HTTPStatusError`` and with
test stubs alike, and never import ``httpx``.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "GOOGLE_QUOTA_REASONS",
    "FailureMessages",
    "classify_http_failure",
    "format_probe_failures",
    "google_quota_reasons",
    "http_status",
    "is_network_error",
    "is_skippable_gate",
    "is_status_429",
    "response_headers",
    "response_quota_reasons",
    "summarize_probe_failures",
]

# Exception class names treated as network failures even when the class does
# not come from httpx (a wrapped or re-raised transport error, or a test stub).
_NETWORK_ERROR_NAMES = frozenset(
    {
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "TimeoutException",
        "NetworkError",
        "RemoteProtocolError",
        "ProxyError",
        "UnsupportedProtocol",
    }
)

# Statuses that mean "this token or plan cannot read this family".
_GATE_STATUSES = frozenset({403, 404})

# Google answers a quota gate with a plain 403 and names the reason only in the
# body. Lower-cased, matched against `google_quota_reasons`.
GOOGLE_QUOTA_REASONS = frozenset({"ratelimitexceeded", "userratelimitexceeded", "quotaexceeded"})


def http_status(exc: BaseException) -> int | None:
    """The HTTP status code of the response attached to ``exc``, if any."""
    return getattr(getattr(exc, "response", None), "status_code", None)


def response_headers(exc: BaseException) -> dict[str, str]:
    """The response headers attached to ``exc``, with lower-cased names.

    Empty when there is no response or its headers are not a mapping.
    """
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers is None:
        return {}
    try:
        return {str(k).lower(): str(v) for k, v in headers.items()}
    except (AttributeError, TypeError):
        # Not a mapping (a stub or unexpected response object): no headers.
        return {}


def google_quota_reasons(body: Any) -> set[str]:
    """Reasons named in a Google-style error body, lower-cased.

    Reads ``error.errors[*].reason`` and ``error.status`` (``RESOURCE_EXHAUSTED``
    on the newer APIs, folded to ``quotaexceeded``). Empty for any other shape.
    """
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return set()
    reasons: set[str] = set()
    for entry in error.get("errors") or []:
        if isinstance(entry, dict) and entry.get("reason"):
            reasons.add(str(entry["reason"]).casefold())
    if str(error.get("status") or "").upper() == "RESOURCE_EXHAUSTED":
        reasons.add("quotaexceeded")
    return reasons


def response_quota_reasons(exc: BaseException) -> set[str]:
    """`google_quota_reasons` of the body attached to ``exc``, if it has one.

    ``httpx.HTTPStatusError`` carries the response; a fixture error carries a
    status only, and a stub may carry anything, so every step is guarded.
    """
    response = getattr(exc, "response", None)
    decode = getattr(response, "json", None)
    if not callable(decode):
        return set()
    try:
        body = decode()
    except (ValueError, TypeError, AttributeError):
        return set()
    return google_quota_reasons(body)


def is_status_429(exc: BaseException) -> bool:
    """The default rate-limit predicate: HTTP 429 Too Many Requests."""
    return http_status(exc) == 429


def is_network_error(exc: BaseException) -> bool:
    """True for transport-level failures: connection, timeout, protocol, proxy."""
    name = type(exc).__name__
    module = type(exc).__module__ or ""
    if module.startswith("httpx") or name in _NETWORK_ERROR_NAMES:
        return True
    folded = name.casefold()
    return "timeout" in folded or "connect" in folded


def is_skippable_gate(
    exc: BaseException,
    *,
    is_rate_limit: Callable[[BaseException], bool] = is_status_429,
    statuses: Collection[int] = _GATE_STATUSES,
) -> bool:
    """True when ``exc`` is a permission or plan gate the sync may skip.

    A rate limit (as judged by the connector's ``is_rate_limit``) is never
    skippable, even when its status is in ``statuses``.
    """
    if is_rate_limit(exc):
        return False
    return http_status(exc) in statuses


def classify_http_failure(
    exc: BaseException,
    *,
    is_rate_limit: Callable[[BaseException], bool] = is_status_429,
) -> str:
    """Map an HTTP or transport failure to a coarse failure class.

    In order: ``rate_limit`` (per ``is_rate_limit``), ``authentication`` (401),
    ``permission`` (403), ``http_<status>`` (any other status), ``network``
    (see `is_network_error`), else ``unknown``. A connector with extra
    provider semantics (an API-level error code, a 403 that means bad
    credentials) handles those first and falls through to this.
    """
    if is_rate_limit(exc):
        return "rate_limit"
    status = http_status(exc)
    if status == 401:
        return "authentication"
    if status == 403:
        return "permission"
    if status is not None:
        return f"http_{status}"
    if is_network_error(exc):
        return "network"
    return "unknown"


# A message is a template string, with ``{probes}`` replaced by the formatted
# probe list, or a callable given that formatted list and the raw failures.
MessageTemplate = str | Callable[[str, Mapping[str, str]], str]


@dataclass(frozen=True)
class FailureMessages:
    """Per-provider wording for `summarize_probe_failures`.

    Each field is a template string in which ``{probes}`` is replaced (by plain
    substitution, so other braces are left alone), or a callable
    ``(probes, failures) -> str`` for a message that depends on which probes
    failed.
    """

    authentication: MessageTemplate
    permission: MessageTemplate
    rate_limit: MessageTemplate
    network: MessageTemplate
    fallback: MessageTemplate


def format_probe_failures(failures: Mapping[str, str]) -> str:
    """``"a (permission), b (network)"``, sorted by probe label."""
    return ", ".join(f"{label} ({klass})" for label, klass in sorted(failures.items()))


def summarize_probe_failures(failures: Mapping[str, str], messages: FailureMessages) -> str:
    """One operator-facing message for a set of failed health probes.

    ``failures`` maps a probe label to its failure class. The most actionable
    class wins: any ``authentication`` failure, then any ``permission``, then
    any ``rate_limit``; ``network`` only when every failure is a network
    failure; otherwise ``fallback``.
    """
    classes = set(failures.values())
    if "authentication" in classes:
        template = messages.authentication
    elif "permission" in classes:
        template = messages.permission
    elif "rate_limit" in classes:
        template = messages.rate_limit
    elif classes == {"network"}:
        template = messages.network
    else:
        template = messages.fallback
    probes = format_probe_failures(failures)
    if isinstance(template, str):
        return template.replace("{probes}", probes)
    return template(probes, failures)
