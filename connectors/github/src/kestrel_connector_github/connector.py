# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Top-level GitHubConnector, wiring configure/authenticate/build_collector/
build_normalizer together. Discovered via the `kestrel.connectors` entry point
declared in pyproject.toml -- Kestrel core never imports this module directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrel.connectors.sdk.base import Collector, Normalizer, Transport
from kestrel.connectors.sdk.manifest import ConnectorManifest

from kestrel_connector_github.auth import build_live_transport
from kestrel_connector_github.client import GitHubClient
from kestrel_connector_github.collector import DEFAULT_DEEP_SCAN_LIMIT, GitHubCollector
from kestrel_connector_github.normalizer import GitHubNormalizer

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "manifest.yaml"


class GitHubConnector:
    manifest: ConnectorManifest = ConnectorManifest.from_yaml(_MANIFEST_PATH)

    def __init__(self) -> None:
        self._org_login: str | None = None
        self._config: dict[str, Any] = {}

    def configure(self, config: dict[str, Any]) -> None:
        self._org_login = config["org_login"]
        self._config = dict(config)

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Transport:
        self.configure(config)
        auth_method = None
        raw = config.get("auth_method")
        if isinstance(raw, str) and raw.strip():
            auth_method = raw.strip()
        return build_live_transport(secrets, auth_method=auth_method)

    def build_collector(self, transport: Transport) -> Collector:
        if self._org_login is None:
            raise RuntimeError("GitHubConnector.configure() must be called before build_collector()")
        enterprise_slug = self._config.get("enterprise_slug") or None
        client = GitHubClient(transport, org_login=self._org_login, enterprise_slug=enterprise_slug)
        return GitHubCollector(
            client,
            # Deep repo posture is expensive per repository, so which repos get
            # it is an operator decision with a risk-tiered default.
            deep_scan_repos=_as_name_list(self._config.get("deep_scan_repos")),
            deep_scan_all=bool(self._config.get("deep_scan_all")),
            deep_scan_limit=_as_limit(self._config.get("deep_scan_limit")),
        )

    def build_normalizer(self) -> Normalizer:
        return GitHubNormalizer()


def _as_name_list(raw: Any) -> list[str] | None:
    """`deep_scan_repos` as a list, accepting the comma-separated string an
    operator is likely to type into a config field."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return None


def _as_limit(raw: Any) -> int:
    if raw is None:
        return DEFAULT_DEEP_SCAN_LIMIT
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_DEEP_SCAN_LIMIT
