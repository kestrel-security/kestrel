# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Core Connector SDK contracts.

These are structural `Protocol`s rather than ABC inheritance so third-party
connector authors don't need to subclass a specific base class chain -- any
object with the right shape satisfies the contract, including test doubles
(see ADR-0005). The lifecycle a connector goes through is:

    configure -> authenticate (live mode only) -> discover -> collect ->
    normalize -> (persisted by the graph writer + findings pipeline, outside
    this module)
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from kestrel.connectors.sdk.manifest import ConnectorManifest


class RawObject(BaseModel):
    """An untouched object as collected from a source system, before
    normalization. Preserved verbatim as `raw_source` on normalized rows."""

    object_type: str
    provider_id: str
    payload: dict[str, Any]
    collected_at: datetime


class NormalizedRelationship(BaseModel):
    """A graph relationship implied by a normalized object, expressed in
    terms of provider ids. Resolved to Kestrel ids by the graph writer once all
    objects in a collection run have been normalized and upserted."""

    edge_type: str
    source_ref: str
    target_ref: str
    access_path: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class NormalizedObject(BaseModel):
    """A single normalized entity ready for upsert into the Kestrel data
    model, along with any graph relationships it implies."""

    kind: str
    provider_id: str
    attributes: dict[str, Any]
    raw_source: dict[str, Any]
    relationships: list[NormalizedRelationship] = Field(default_factory=list)


class HealthCheckResult(BaseModel):
    healthy: bool
    message: str
    checked_permissions: dict[str, bool] = Field(default_factory=dict)


@runtime_checkable
class Transport(Protocol):
    """Injected into a Collector so it never touches an HTTP client
    directly -- this indirection is what makes fixture-mode testing possible
    with zero live credentials (see sdk/fixtures.py and sdk/transport.py).

    ``request`` returns the decoded JSON body, or ``None`` for a success
    without a body (204 No Content). A transport may additionally offer
    ``request_raw`` (see `RawResponse`); callers reach it through the
    module-level `request_raw` helper so a transport without it still works.
    """

    def request(self, method: str, path: str, **kwargs: Any) -> Any: ...

    def paginate(self, method: str, path: str, **kwargs: Any) -> Iterable[dict[str, Any]]: ...


@dataclass(frozen=True)
class RawResponse:
    """An undecoded response: status, lower-cased headers and the body bytes.

    `Transport.request` decodes JSON, which is right for every provider list
    endpoint but loses two things a few calls need: response headers (Slack
    answers ``ok: false, error: ratelimited`` on HTTP 200 and names the wait
    in ``Retry-After``) and non-JSON bodies (Slack's analytics export is a
    gzipped NDJSON file). Those calls go through `request_raw` instead.
    """

    status_code: int
    headers: Mapping[str, str] = field(default_factory=dict)
    content: bytes = b""

    def json(self) -> Any:
        """The body decoded as JSON, or ``None`` for an empty body."""
        if not self.content:
            return None
        return json.loads(self.content)


def request_raw(transport: Transport, method: str, path: str, **kwargs: Any) -> RawResponse:
    """`RawResponse` from any Transport.

    Uses the transport's own ``request_raw`` when it has one (the live and
    fixture transports do). A transport that only implements the Protocol's
    ``request`` -- a test double -- is wrapped: its decoded body is re-encoded,
    the status is 200 and there are no headers, which is exactly what such a
    double would have answered anyway.
    """
    native = getattr(transport, "request_raw", None)
    if callable(native):
        result = native(method, path, **kwargs)
        if isinstance(result, RawResponse):
            return result
    body = transport.request(method, path, **kwargs)
    content = b"" if body is None else json.dumps(body).encode("utf-8")
    return RawResponse(status_code=200, headers={}, content=content)


@runtime_checkable
class Collector(Protocol):
    """One per connector. Pulls RawObjects from the source system (or
    fixtures, via an injected Transport)."""

    def discover(self) -> list[str]:
        """Object types this instance can actually collect -- may be fewer
        than the manifest's full list, depending on granted scopes."""
        ...

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        """`since` supports incremental sync; connectors that don't support
        it ignore the argument and always full-sync.

        A collector may additionally expose a ``skipped_object_types:
        dict[str, str]`` attribute mapping an object type it could not read to
        a coarse failure class (e.g. a plan-gated audit log returning 403).
        `run_collection` copies it onto the CollectionResult, and the sync
        pipeline downgrades the run to PARTIAL_FAILURE and suppresses deletion
        detection so a partial inventory is never read as mass deletion. The
        attribute is optional -- connectors that fail hard omit it.
        """
        ...

    def health_check(self) -> HealthCheckResult: ...


@runtime_checkable
class Normalizer(Protocol):
    """One per connector. Pure function-ish: RawObjects in, NormalizedObjects
    out, no I/O -- fully unit-testable without network or DB access."""

    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]: ...


@runtime_checkable
class Connector(Protocol):
    """Top-level connector contract tying configuration + auth + collector +
    normalizer together. This is what the registry discovers via entry
    points (see sdk/registry.py)."""

    manifest: ConnectorManifest

    def configure(self, config: dict[str, Any]) -> None:
        """Stores non-secret configuration (e.g. an org login) needed by the
        collector, independent of which Transport ends up being used. Always
        called before build_collector, in both live and fixture modes."""
        ...

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        """Builds a live Transport from config + secrets. Only called in
        live mode -- fixture-mode callers supply a Transport directly (see
        connectors/sdk/runner.py) and never call this method, which is what
        makes "testable entirely against fixtures with no live credentials"
        concretely true."""
        ...

    def build_collector(self, transport: Transport) -> Collector: ...

    def build_normalizer(self) -> Normalizer: ...
