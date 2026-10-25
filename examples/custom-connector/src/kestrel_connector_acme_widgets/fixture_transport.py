# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Builds a FixtureTransport for this connector's bundled fixtures/, used
by unit tests and `kestrel connector validate` to prove it works with zero
live credentials."""

from __future__ import annotations

from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureTransport

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


def build_fixture_transport() -> FixtureTransport:
    return FixtureTransport(
        fixtures_dir=FIXTURES_DIR,
        mapping={"GET /users": "users.json"},
    )
