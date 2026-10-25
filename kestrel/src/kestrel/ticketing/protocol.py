# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""TicketProvider protocol + shared create request/result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True)
class TicketCreateRequest:
    """Normalized payload every provider turns into a tracker issue."""

    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    finding_id: str | None = None


@dataclass(frozen=True)
class TicketCreateResult:
    external_id: str
    url: str
    raw: dict[str, Any] | None = None


@runtime_checkable
class TicketProvider(Protocol):
    """Outbound ticket tracker adapter.

    Discovered via builtins + ``kestrel.ticket_providers`` entry points.
    Implementations must never log credentials; callers inject httpx clients
    for tests (mock HTTP — never hit live trackers from fixtures).
    """

    provider_id: str

    def create_issue(
        self,
        *,
        token: str,
        config: dict[str, Any],
        request: TicketCreateRequest,
        http_client: httpx.Client | None = None,
        dry_run: bool = False,
    ) -> TicketCreateResult: ...
