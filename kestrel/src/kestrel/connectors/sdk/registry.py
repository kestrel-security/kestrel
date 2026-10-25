# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Discovers installed connectors via the `kestrel.connectors` entry-point
group, so core code never needs to import a specific connector package --
this is what makes "connector development without modifying core" real.

Also scans `KESTREL_CUSTOM_CONNECTORS_DIR` so a drop-in package
appears without a Dockerfile rebuild. Entry points win on name collision.
"""

from __future__ import annotations

import importlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kestrel.connectors.sdk.base import Connector
    from kestrel.connectors.sdk.fixtures import FixtureTransport

ENTRY_POINT_GROUP = "kestrel.connectors"
CUSTOM_CONNECTORS_DIR_ENV = "KESTREL_CUSTOM_CONNECTORS_DIR"
_BUILTIN_CONNECTORS = frozenset({"github", "google_workspace", "slack", "okta"})
_LOG = logging.getLogger(__name__)


@dataclass
class ConnectorRegistration:
    name: str
    connector_class: type[Connector]
    source: str = "builtin"
    fixture_transport_builder: Callable[[], Any] | None = None


def _entry_point_source(name: str) -> str:
    return "builtin" if name in _BUILTIN_CONNECTORS else "custom"


def _discover_plugin_dir() -> dict[str, ConnectorRegistration]:
    raw = os.environ.get(CUSTOM_CONNECTORS_DIR_ENV, "").strip()
    if not raw:
        return {}
    root = Path(raw)
    if not root.is_dir():
        _LOG.warning("custom connectors dir %s is not a directory", root)
        return {}

    from kestrel.connectors.discovery import load_connector_from_path

    found: dict[str, ConnectorRegistration] = {}
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not (child / "manifest.yaml").is_file():
            continue
        try:
            manifest, connector_class, builder = load_connector_from_path(child)
        except Exception:  # noqa: BLE001 -- one broken plugin must not hide the others; logged
            _LOG.exception("failed to load custom connector from %s", child)
            continue
        found[manifest.name] = ConnectorRegistration(
            name=manifest.name,
            connector_class=connector_class,
            source="custom",
            fixture_transport_builder=builder,
        )
    return found


def discover_connectors() -> dict[str, ConnectorRegistration]:
    """Returns {connector_name: ConnectorRegistration} for every installed
    connector package plus any plugin-directory packages."""
    from kestrel.connectors.readonly_scopes import assert_read_only_scopes

    discovered: dict[str, ConnectorRegistration] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name in discovered:
            continue
        connector_class = ep.load()
        manifest = getattr(connector_class, "manifest", None)
        if manifest is not None:
            assert_read_only_scopes(manifest)
        discovered[ep.name] = ConnectorRegistration(
            name=ep.name,
            connector_class=connector_class,
            source=_entry_point_source(ep.name),
        )
    for name, reg in _discover_plugin_dir().items():
        if name not in discovered:
            discovered[name] = reg
    return discovered


def load_connector(name: str) -> Connector:
    discovered = discover_connectors()
    if name not in discovered:
        available = ", ".join(sorted(discovered)) or "(none installed)"
        raise ValueError(f"Connector '{name}' is not installed. Available: {available}")
    return discovered[name].connector_class()


def load_fixture_transport_builder(name: str) -> Callable[[], FixtureTransport]:
    """Every connector built on this SDK ships a `fixture_transport.py`
    module with a `build_fixture_transport()` function (see the connector
    authoring tutorial) -- this is how callers that only know a connector by
    name (the worker task, `kestrel sync`) build a FixtureTransport for
    SyncMode.FIXTURES instances without hardcoding a specific connector's
    import path.
    """
    discovered = discover_connectors()
    stored = discovered.get(name)
    if stored is not None and stored.fixture_transport_builder is not None:
        return stored.fixture_transport_builder
    module_name = f"kestrel_connector_{name.replace('-', '_')}"
    fixture_module = importlib.import_module(f"{module_name}.fixture_transport")
    return fixture_module.build_fixture_transport
