# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Top-level SlackConnector. Discovered via the `kestrel.connectors` entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_slack.auth import build_audit_transport, build_live_transport
from kestrel_connector_slack.client import SlackClient
from kestrel_connector_slack.collector import SlackCollector
from kestrel_connector_slack.normalizer import SlackNormalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class SlackConnector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._team_id: str | None = None
        self._enterprise_id: str | None = None
        self._secrets: dict[str, str] | None = None

    def configure(self, config: dict[str, Any]) -> None:
        self._team_id = config["team_id"]
        enterprise = config.get("enterprise_id")
        self._enterprise_id = str(enterprise).strip() if enterprise else None

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        self._secrets = dict(secrets)
        return build_live_transport(secrets)

    def build_collector(self, transport: Transport) -> Collector:
        if self._team_id is None:
            raise RuntimeError("SlackConnector.configure() must be called before build_collector()")
        audit_transport: Transport | None = None
        if self._secrets is not None:
            audit_transport = build_audit_transport(self._secrets)
        return SlackCollector(
            SlackClient(
                transport,
                team_id=self._team_id,
                enterprise_id=self._enterprise_id,
                audit_transport=audit_transport,
            )
        )

    def build_normalizer(self) -> Normalizer:
        return SlackNormalizer()
