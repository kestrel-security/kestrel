# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Top-level AcmeWidgetsConnector, wiring configure/authenticate/
build_collector/build_normalizer together. Discovered via the
`kestrel.connectors` entry point declared in pyproject.toml once this
connector is added to the workspace and `uv sync` has run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_acme_widgets.auth import build_live_transport
from kestrel_connector_acme_widgets.client import AcmeWidgetsClient
from kestrel_connector_acme_widgets.collector import AcmeWidgetsCollector
from kestrel_connector_acme_widgets.normalizer import AcmeWidgetsNormalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class AcmeWidgetsConnector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._config: dict[str, Any] = {}

    def configure(self, config: dict[str, Any]) -> None:
        self._config = config

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        return build_live_transport(config, secrets)

    def build_collector(self, transport: Transport) -> Collector:
        client = AcmeWidgetsClient(transport, base_url=self._config.get("base_url", ""))
        return AcmeWidgetsCollector(client)

    def build_normalizer(self) -> Normalizer:
        return AcmeWidgetsNormalizer()
