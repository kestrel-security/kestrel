# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Fixture-mode Transport: replays canned JSON responses instead of making
live HTTP calls, so connectors are fully testable without credentials or
network access (see ADR-0005).

Connectors are responsible for building request paths that already include
any query string needed to disambiguate the call (e.g.
`/orgs/acme/members?role=admin`), and for supplying an explicit
`signature -> fixture file` mapping. This keeps fixture lookups exact-match
and avoids trying to infer path-parameter templates from concrete requests.

The one exception is `volatile_params`. A cursored call carries a watermark
that differs on every run (`&since=2026-08-30T12:00:00Z`), so no exact-match
signature can ever cover it -- which is why the incremental paths that Okta
and Slack have plumbed since they shipped had no offline coverage at all.
Naming those parameters lets the incremental call fall back to the same
fixture as the full call, which is the right answer: fixtures represent a
complete result set, and what is being tested offline is that the connector
builds the cursored request and normalizes the response, not that the provider
filters correctly.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from kestrel.connectors.sdk.base import RawResponse


class FixtureNotFoundError(RuntimeError):
    pass


@dataclass(frozen=True)
class _StatusOnlyResponse:
    """Enough of an HTTP response for a connector's error classifier.

    Classifiers read `exc.response.status_code` (see e.g.
    `kestrel_connector_github.http`), so a fixture-mode error only has to carry
    that much to travel the same path a live error would.
    """

    status_code: int


class FixtureHTTPError(RuntimeError):
    """A status a fixture deliberately reproduces, rather than a missing file.

    Absence is part of an API's contract, not a gap in the dataset: GitHub 404s
    an unprotected branch, a plan without a feature 403s, and the connector code
    that reads those as answers rather than failures has to be exercisable
    offline. Without this, a fixture set could only express success, and every
    absence path stayed untested until a live tenant hit it.
    """

    def __init__(self, status_code: int, signature: str) -> None:
        super().__init__(f"Fixture reproduces HTTP {status_code} for '{signature}'")
        self.response = _StatusOnlyResponse(status_code=status_code)


@dataclass(frozen=True)
class FixtureStatus:
    """Map a request signature to a status instead of a file.

    ``mapping["GET /x"] = FixtureStatus(404)`` reproduces an error the
    connector classifies. ``FixtureStatus(204)`` reproduces a *success without
    a body*: `request` answers ``None``, exactly as `LiveHTTPTransport` does
    for GitHub's ``204 No Content`` on the vulnerability-alerts probe. A JSON
    file cannot express "no body", so without this the fixture path returned
    ``{}`` where live returned nothing, and the live-only failure went unseen.
    """

    status_code: int

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


def request_signature(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


class FixtureTransport:
    """Implements the Transport protocol. `mapping` keys are request
    signatures (`METHOD path`, including any query string), values are
    fixture file names relative to `fixtures_dir`."""

    def __init__(
        self,
        fixtures_dir: str | Path,
        mapping: dict[str, str | FixtureStatus],
        *,
        volatile_params: Collection[str] | None = None,
    ) -> None:
        self.fixtures_dir = Path(fixtures_dir)
        self.mapping = mapping
        # Query parameters whose value changes every run (an incremental
        # watermark). Stripped on a miss so the cursored call resolves to the
        # same fixture as the uncursored one.
        self.volatile_params = frozenset(volatile_params or ())
        self._cache: dict[str, Any] = {}

    def _without_volatile_params(self, signature: str) -> str | None:
        """`signature` with `volatile_params` dropped, or None if unchanged."""
        if not self.volatile_params:
            return None
        method, _, path = signature.partition(" ")
        split = urlsplit(path)
        pairs = parse_qsl(split.query, keep_blank_values=True)
        kept = [(key, value) for key, value in pairs if key not in self.volatile_params]
        if len(kept) == len(pairs):
            return None
        stripped = urlunsplit((split.scheme, split.netloc, split.path, urlencode(kept), split.fragment))
        return f"{method} {stripped}"

    def _resolve(self, signature: str) -> tuple[str, str | FixtureStatus]:
        """The mapping entry for ``signature``, after the volatile-param fallback."""
        if signature not in self.mapping:
            fallback = self._without_volatile_params(signature)
            if fallback is not None and fallback in self.mapping:
                signature = fallback
        if signature not in self.mapping:
            raise FixtureNotFoundError(
                f"No fixture mapped for request '{signature}'. Known signatures: {sorted(self.mapping)}"
            )
        return signature, self.mapping[signature]

    def _read(self, filename: str) -> Any:
        if filename not in self._cache:
            fixture_path = self.fixtures_dir / filename
            self._cache[filename] = json.loads(fixture_path.read_text())
        return self._cache[filename]

    def _load(self, signature: str) -> Any:
        signature, mapped = self._resolve(signature)
        if isinstance(mapped, FixtureStatus):
            if mapped.is_success:
                return None
            raise FixtureHTTPError(mapped.status_code, signature)
        return self._read(mapped)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._load(request_signature(method, path))

    def request_raw(self, method: str, path: str, **kwargs: Any) -> RawResponse:
        """The fixture as undecoded bytes, with no headers.

        A ``FixtureStatus`` success carries its status and an empty body; a file
        is re-encoded, so a connector that parses raw bodies itself (Slack's
        analytics export) reads the same fixture the JSON path would.
        """
        signature, mapped = self._resolve(request_signature(method, path))
        if isinstance(mapped, FixtureStatus):
            if mapped.is_success:
                return RawResponse(status_code=mapped.status_code)
            raise FixtureHTTPError(mapped.status_code, signature)
        return RawResponse(status_code=200, content=json.dumps(self._read(mapped)).encode("utf-8"))

    def paginate(self, method: str, path: str, **kwargs: Any) -> Iterable[dict[str, Any]]:
        """Fixtures represent an already-complete result list; connectors
        that call paginate() against a FixtureTransport get the full fixture
        list back as a single "page" since there is no real pagination to
        replay."""
        data = self.request(method, path, **kwargs)
        if isinstance(data, list):
            yield from data
        elif data is not None:
            yield data
