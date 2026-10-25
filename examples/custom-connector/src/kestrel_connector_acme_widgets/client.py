# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Thin typed wrapper over a Transport. Replace these methods with real
calls to Acme Widgets's API -- every method's path doubles as the request
signature FixtureTransport uses to find its matching fixture file."""

from __future__ import annotations

from typing import Any

from kestrel.connectors.sdk.base import Transport


class AcmeWidgetsClient:
    def __init__(self, transport: Transport, base_url: str) -> None:
        self.transport = transport
        self.base_url = base_url

    def list_users(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", "/users"))
