# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Live-mode Transport: wraps an HTTP client for real API calls.

Paginates via RFC 5988 `Link` headers and retries throttled requests. Rate
limiting is handled in three shapes because providers disagree about which
status code means "slow down":

* **429 + Retry-After** — the common case (Okta, Slack, GitHub secondary
  limits).
* **403 + x-ratelimit-remaining: 0** — GitHub's *primary* rate limit. Without
  this branch a throttled GitHub sync surfaces as a permission error, which
  reads as "the token lost access" and, if a caller treats 403 as skippable,
  silently drops an entire object family from the inventory.
* **403 whose JSON body names a quota reason** — Google's shape
  (``rateLimitExceeded``, ``userRateLimitExceeded``, ``quotaExceeded``). The
  headers carry nothing, so the body is read on 403s only.

Transient server failures are retried too: a single 502 or read timeout on
page 300 of a long inventory walk used to fail the whole run, and Celery then
re-collected everything from page 1. Only idempotent requests are retried --
GET and HEAD by default, plus whatever a connector declares (GitHub's GraphQL
and Slack's admin ``list`` methods are read-only POSTs).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Collection, Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from kestrel.connectors.sdk.base import RawResponse
from kestrel.connectors.sdk.failures import GOOGLE_QUOTA_REASONS, google_quota_reasons
from kestrel.security.ssrf import validate_connector_url

_LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    import httpx

# Safety cap for Link-header walks (Okta/GitHub large orgs).
_MAX_PAGES = 10_000
_MAX_RATE_LIMIT_RETRIES = 3
# Longest we will block a worker waiting out a throttle. GitHub primary limits
# can reset up to an hour away; holding a sync open that long would look like a
# hang and pin a Celery slot, so anything beyond this fails the run instead.
_MAX_RATE_LIMIT_WAIT_SECONDS = 60.0

# Transient server failures: one retry ladder of `_MAX_ATTEMPTS` attempts in
# total (the first try plus two retries), with capped exponential backoff.
_RETRYABLE_SERVER_STATUSES = frozenset({500, 502, 503, 504})
_MAX_ATTEMPTS = 3
_MAX_SERVER_ERROR_BACKOFF_SECONDS = 8.0

DEFAULT_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})


class LiveHTTPTransport:
    """Implements the Transport protocol over httpx. Paginates via RFC 5988
    `Link` headers (GitHub / Okta pagination style)."""

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str],
        timeout: float = 30.0,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
        auth_refresh: Callable[[], dict[str, str]] | None = None,
        idempotent_methods: Collection[str] = DEFAULT_IDEMPOTENT_METHODS,
    ) -> None:
        """``transport`` and ``sleep`` are seams, not features.

        Both default to today's behavior (a real network client and
        ``time.sleep``). Passing an ``httpx.MockTransport`` lets a caller
        exercise the real pagination and 429-retry logic against canned
        responses, and passing ``sleep`` keeps the backoff path from actually
        sleeping while still recording the delays it would have taken.

        ``auth_refresh`` returns a fresh header set and is called at most once
        per request, on a 401. Some providers issue short-lived credentials --
        a GitHub App installation token expires after an hour -- so a long
        inventory walk that started with a valid token can begin failing
        mid-run. Refreshing here rather than in the connector means every page
        of a paginated walk is covered without the connector re-implementing
        retry.

        ``idempotent_methods`` names the HTTP methods that may be retried after
        a 5xx or a transport error. GET and HEAD always are; a connector whose
        POSTs are read-only queries (GraphQL, Slack's admin ``list`` calls) adds
        POST. Anything else fails on the first server error, since replaying a
        write the provider may already have applied is worse than a failed run.
        """
        import httpx

        validate_connector_url(base_url, field="base_url", require_https=True)
        self._sleep: Callable[[float], None] = sleep if sleep is not None else time.sleep
        self._auth_refresh = auth_refresh
        self._idempotent_methods = frozenset(method.upper() for method in idempotent_methods)
        self.client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout, transport=transport)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        """The decoded JSON body, or ``None`` for a success without a body.

        GitHub answers ``GET /repos/{org}/{repo}/vulnerability-alerts`` with
        204 No Content when alerts are enabled; decoding that as JSON raised a
        ``JSONDecodeError`` that no classifier could read, so every org with
        alerts enabled on a deep-scan repository failed its sync.
        """
        response = self._request_with_retries(method, path, **kwargs)
        return _decode_body(response)

    def request_raw(self, method: str, path: str, **kwargs: Any) -> RawResponse:
        """Status, headers and body bytes, for the few calls that need them
        (see `kestrel.connectors.sdk.base.RawResponse`). Errors raise exactly
        as they do from `request`."""
        response = self._request_with_retries(method, path, **kwargs)
        return RawResponse(
            status_code=response.status_code,
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            content=response.content,
        )

    def paginate(self, method: str, path: str, **kwargs: Any) -> Iterable[dict[str, Any]]:
        next_url: str | None = path
        pages = 0
        while next_url:
            pages += 1
            if pages > _MAX_PAGES:
                raise RuntimeError(f"LiveHTTPTransport.paginate exceeded {_MAX_PAGES} pages for {method} {path}")
            response = self._request_with_retries(method, next_url, **kwargs)
            data = _decode_body(response)
            if isinstance(data, list):
                yield from data
            elif data is not None:
                yield data
            next_url = self._same_origin_next(response.links.get("next", {}).get("url"))
            kwargs = {}  # query params are already encoded in next_url

    def _request_with_retries(self, method: str, url: str, **kwargs: Any) -> Any:
        import httpx

        retryable = method.upper() in self._idempotent_methods
        throttles = 0
        attempts = 0
        refreshed = False
        while True:
            attempts += 1
            try:
                response = self.client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                # Connection reset, read timeout, protocol error: the request may
                # never have reached the provider. Safe to replay when idempotent.
                if not retryable or attempts >= _MAX_ATTEMPTS:
                    raise
                _LOG.info("connector request %s %s: %s; retrying", method, url, type(exc).__name__)
                self._sleep(_server_error_delay(attempts))
                continue
            if response.status_code == 401 and self._auth_refresh is not None and not refreshed:
                refreshed = True
                if self._refresh_auth():
                    continue
            if throttles < _MAX_RATE_LIMIT_RETRIES:
                delay = _throttle_delay(response, throttles + 1)
                if delay is not None:
                    throttles += 1
                    self._sleep(delay)
                    continue
            if response.status_code in _RETRYABLE_SERVER_STATUSES and retryable and attempts < _MAX_ATTEMPTS:
                self._sleep(_server_error_delay(attempts))
                continue
            response.raise_for_status()
            return response

    def _refresh_auth(self) -> bool:
        """Re-mint credentials and apply them to the client. False on failure.

        A failed refresh must not mask the original 401 -- the caller falls
        through to `raise_for_status()` so the operator sees an authentication
        error rather than a minting stack trace.
        """
        if self._auth_refresh is None:
            return False
        try:
            headers = self._auth_refresh()
        except Exception as exc:  # noqa: BLE001 -- any minting failure; the 401 is what the operator should see
            # Type only: a minting error can echo token-endpoint responses.
            _LOG.warning("connector credential refresh failed: %s", type(exc).__name__)
            return False
        if not headers:
            return False
        self.client.headers.update(headers)
        return True

    def _same_origin_next(self, next_url: str | None) -> str | None:
        """Return a request path for the next page, refusing cross-host Link targets."""
        if not next_url:
            return None
        parsed = urlparse(next_url)
        if not parsed.scheme and not parsed.netloc:
            return next_url
        base = urlparse(str(self.client.base_url))
        if parsed.netloc.casefold() != base.netloc.casefold():
            raise RuntimeError(
                f"Refusing pagination next URL host {parsed.netloc!r} (expected same origin as {base.netloc!r})"
            )
        path = parsed.path or "/"
        if parsed.query:
            return f"{path}?{parsed.query}"
        return path


def _decode_body(response: Any) -> Any:
    """JSON body, or None when there is none (204, or an empty 200)."""
    if response.status_code == 204 or not response.content:
        return None
    return response.json()


def _server_error_delay(attempt: int) -> float:
    """Backoff before retry number ``attempt`` (1-based): 1 s, 2 s, ... capped."""
    return min(2.0 ** (attempt - 1), _MAX_SERVER_ERROR_BACKOFF_SECONDS)


def _retry_after_seconds(response: Any) -> float | None:
    """`Retry-After` in delta-seconds form, if present and parseable."""
    raw = str(response.headers.get("Retry-After", "")).strip()
    if not raw.isdigit():
        return None
    return float(raw)


def _rate_limit_reset_seconds(response: Any, *, now: float | None = None) -> float | None:
    """Seconds until `x-ratelimit-reset`, when the quota is actually exhausted.

    Only meaningful with `x-ratelimit-remaining: 0` -- the reset timestamp is
    present on every response, so keying off it alone would treat healthy
    responses as throttled.
    """
    headers = response.headers
    if str(headers.get("x-ratelimit-remaining", "")).strip() != "0":
        return None
    raw = str(headers.get("x-ratelimit-reset", "")).strip()
    try:
        reset_at = float(raw)
    except ValueError:
        return None
    clock = time.time() if now is None else now
    return max(0.0, reset_at - clock)


def _body_says_rate_limited(response: Any) -> bool:
    """Google's quota gate: read on 403s only, so a provider that answers 403
    with a non-JSON body costs nothing extra on the happy path."""
    try:
        body = response.json()
    except ValueError:
        return False
    return bool(google_quota_reasons(body) & GOOGLE_QUOTA_REASONS)


def _throttle_delay(response: Any, attempt: int) -> float | None:
    """How long to wait before retrying, or None if this isn't a throttle.

    Returns None (rather than a delay) when the wait would exceed
    `_MAX_RATE_LIMIT_WAIT_SECONDS`, so the caller raises the underlying HTTP
    error instead of blocking a worker for the full reset window.
    """
    status = response.status_code
    if status not in {403, 429}:
        return None

    reset_in = _rate_limit_reset_seconds(response)
    retry_after = _retry_after_seconds(response)

    if status == 403 and reset_in is None and retry_after is None:
        # Google names its quota gates in the body rather than the headers.
        # Any other plain 403 is a permission or plan gate, not a throttle.
        if _body_says_rate_limited(response):
            return min(2.0**attempt, 8.0)
        return None

    if reset_in is not None:
        if reset_in > _MAX_RATE_LIMIT_WAIT_SECONDS:
            return None
        # Small cushion: retrying exactly at the boundary tends to race the
        # provider's own clock and burn a retry.
        return reset_in + 1.0
    if retry_after is not None:
        if retry_after > _MAX_RATE_LIMIT_WAIT_SECONDS:
            return None
        return retry_after
    return min(2.0**attempt, 8.0)
