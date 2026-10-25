# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Translates AcmeWidgetsClient responses into RawObjects, one per manifest
object_type."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject

from kestrel_connector_acme_widgets.client import AcmeWidgetsClient

OBJECT_TYPES = ["user"]


class AcmeWidgetsCollector:
    def __init__(self, client: AcmeWidgetsClient) -> None:
        self.client = client

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        users = self.client.list_users()
        return HealthCheckResult(healthy=True, message=f"Connected, found {len(users)} users")

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        if object_type != "user":
            raise ValueError(f"Unsupported object_type '{object_type}'")
        now = datetime.now(UTC)
        for user in self.client.list_users():
            yield RawObject(object_type="user", provider_id=str(user["id"]), payload=user, collected_at=now)
