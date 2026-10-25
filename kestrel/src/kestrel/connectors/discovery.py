# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Loads a connector package directly from a directory path, without
requiring it to be registered as a uv workspace member or entry point
first -- this is what lets `kestrel connector validate` work immediately
after `kestrel connector create`, before a contributor has wired up
packaging (see connectors/sdk/registry.py for the entry-point-based path
used once a connector is actually installed).
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path

from kestrel.connectors.sdk.manifest import ConnectorManifest

_REQUIRED_ATTRS = ("manifest", "configure", "authenticate", "build_collector", "build_normalizer")


def _find_connector_class(module: object) -> type:
    """Finds the class conforming to the Connector protocol by structural
    duck-typing rather than guessing a class name from the connector's
    name -- naive PascalCase conversion breaks for names with irregular
    capitalization (e.g. "github" -> "GitHub", not "Github")."""
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if isinstance(obj, type) and all(hasattr(obj, attr) for attr in _REQUIRED_ATTRS):
            return obj
    raise ValueError(f"No Connector-conforming class found in {module!r}")


def load_connector_from_path(path: Path) -> tuple[ConnectorManifest, type, Callable]:
    """Returns (manifest, connector_class, build_fixture_transport)."""
    from kestrel.connectors.readonly_scopes import assert_read_only_scopes

    manifest = ConnectorManifest.from_yaml(path / "manifest.yaml")
    assert_read_only_scopes(manifest)

    src_dir = path / "src"
    if src_dir.exists() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    module_name = f"kestrel_connector_{manifest.name.replace('-', '_')}"
    connector_module = importlib.import_module(f"{module_name}.connector")
    fixture_module = importlib.import_module(f"{module_name}.fixture_transport")

    connector_class = _find_connector_class(connector_module)
    return manifest, connector_class, fixture_module.build_fixture_transport
