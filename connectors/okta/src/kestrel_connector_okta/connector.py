# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Top-level OktaConnector. Discovered via the `kestrel.connectors` entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_okta.auth import build_live_transport, normalize_okta_org_url
from kestrel_connector_okta.client import OktaClient
from kestrel_connector_okta.collector import OktaCollector
from kestrel_connector_okta.normalizer import OktaNormalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class OktaConnector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._org_url: str | None = None

    def configure(self, config: dict[str, Any]) -> None:
        self._org_url = normalize_okta_org_url(str(config["org_url"]))

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        assert self._org_url is not None
        return build_live_transport(self._org_url, secrets)

    def build_collector(self, transport: Transport) -> Collector:
        if self._org_url is None:
            raise RuntimeError("OktaConnector.configure() must be called before build_collector()")
        return OktaCollector(OktaClient(transport, org_url=self._org_url))

    def build_normalizer(self) -> Normalizer:
        return OktaNormalizer()
