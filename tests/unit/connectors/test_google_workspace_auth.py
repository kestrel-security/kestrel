# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Google Workspace auth: scopes stay aligned with the manifest."""

from __future__ import annotations

from pathlib import Path

import yaml
from kestrel_connector_google_workspace.auth import DEFAULT_SCOPES, load_manifest_scopes


def test_default_scopes_match_manifest_required_scopes() -> None:
    manifest = yaml.safe_load(
        (Path(__file__).resolve().parents[3] / "connectors/google_workspace/manifest.yaml").read_text()
    )
    declared = tuple(manifest["required_scopes"])
    assert declared == DEFAULT_SCOPES
    assert load_manifest_scopes() == declared


def test_default_scopes_include_directory_and_groups_settings() -> None:
    # Regression: minting a 5-scope subset left domains / OUs / group settings /
    # user tokens returning 403 on every live tenant.
    joined = " ".join(DEFAULT_SCOPES)
    assert "admin.directory.domain.readonly" in joined
    assert "admin.directory.orgunit.readonly" in joined
    assert "apps.groups.settings" in joined
    assert "admin.directory.user.security" in joined
    assert "admin.reports.audit.readonly" in joined
