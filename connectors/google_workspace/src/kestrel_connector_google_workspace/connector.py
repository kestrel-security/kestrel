# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Top-level GoogleWorkspaceConnector, wiring configure/authenticate/
build_collector/build_normalizer together. Discovered via the
`kestrel.connectors` entry point declared in pyproject.toml -- Kestrel core never
imports this module directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_google_workspace.auth import build_live_transport
from kestrel_connector_google_workspace.client import GoogleWorkspaceClient
from kestrel_connector_google_workspace.collector import GoogleWorkspaceCollector
from kestrel_connector_google_workspace.normalizer import GoogleWorkspaceNormalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class GoogleWorkspaceConnector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._domain: str | None = None

    def configure(self, config: dict[str, Any]) -> None:
        self._domain = config["domain"]

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        return build_live_transport(secrets)

    def build_collector(self, transport: Transport) -> Collector:
        if self._domain is None:
            raise RuntimeError("GoogleWorkspaceConnector.configure() must be called before build_collector()")
        client = GoogleWorkspaceClient(transport, domain=self._domain)
        return GoogleWorkspaceCollector(client)

    def build_normalizer(self) -> Normalizer:
        return GoogleWorkspaceNormalizer()
