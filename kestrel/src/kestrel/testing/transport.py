# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""A recording implementation of the connector SDK ``Transport`` protocol.

Every connector test suite had grown its own duck-typed copy of this class
(okta, google_workspace, slack, github), each
slightly different, so a change to the Transport protocol broke them one at a
time. This is the single shipped version.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


class TransportPathNotFound(KeyError):
    """Raised when a test asks for a path the RecordingTransport wasn't given."""


class RecordingTransport:
    """Serves canned responses by path and records every call.

    ``responses`` maps a request path (exactly as the client under test builds
    it, query string included) to whatever that path should return. A list is
    the common shape for ``paginate``; a dict is the common shape for
    ``request``.

    Args:
        responses: path -> canned response body.
        strict: when True (the default) an unknown path raises
            ``TransportPathNotFound`` -- a test that silently gets an empty
            list back for a path it typo'd is worse than a failing one. Pass
            ``strict=False`` for the older "unknown path yields nothing"
            behavior.
    """

    def __init__(self, responses: dict[str, Any] | None = None, *, strict: bool = True) -> None:
        self.responses: dict[str, Any] = dict(responses or {})
        self.strict = strict
        self.request_calls: list[tuple[str, str]] = []
        self.paginate_calls: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str, str]] = []

    def set_response(self, path: str, value: Any) -> None:
        self.responses[path] = value

    def _lookup(self, path: str, default: Any) -> Any:
        if path in self.responses:
            return self.responses[path]
        if self.strict:
            raise TransportPathNotFound(
                f"RecordingTransport has no response for {path!r}; known paths: {sorted(self.responses)}"
            )
        return default

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.request_calls.append((method, path))
        self.calls.append(("request", method, path))
        return self._lookup(path, {})

    def paginate(self, method: str, path: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        self.paginate_calls.append((method, path))
        self.calls.append(("paginate", method, path))
        body = self._lookup(path, [])
        if isinstance(body, list):
            yield from body
        else:
            yield body

    @property
    def paginate_paths(self) -> list[str]:
        return [path for _method, path in self.paginate_calls]

    @property
    def request_paths(self) -> list[str]:
        return [path for _method, path in self.request_calls]
