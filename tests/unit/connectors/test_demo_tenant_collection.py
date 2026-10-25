# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- the demo tenants sync cleanly over their fixtures.

`resource_type` is a free string in `NormalizedObject.attributes` and only
becomes `ResourceType(...)` inside the upsert, so a normalizer can emit a value
the enum (and the Postgres type) has never heard of and nothing notices until a
real sync crashes. That happened with Slack workflows: `kestrel demo up` failed
on the Slack tenant. Run each demo tenant over both the bundled fixtures and
the generated demo estate, which is what `demo up` syncs.

A fixture that skips an object family turns the run into PARTIAL_FAILURE and
leaves that family out of the demo, so the fixtures must not skip anything.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from kestrel.cli.demo import _demo_tenants
from kestrel.connectors.sdk.runner import run_collection
from kestrel.db.models.resource import ResourceType
from kestrel.demo.generate import generate_fixtures

VALID = {member.value for member in ResourceType}


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return generate_fixtures(tmp_path_factory.mktemp("fixtures"), now=datetime(2026, 8, 28, tzinfo=UTC))


@pytest.mark.parametrize("source", ["bundled", "generated"])
@pytest.mark.parametrize("tenant", _demo_tenants(), ids=lambda t: t.connector_name)
def test_demo_tenant_collects_cleanly(tenant, source: str, generated: dict[str, Path]) -> None:
    fixtures_dir = tenant.fixtures_dir if source == "bundled" else generated[tenant.connector_name]
    result = run_collection(
        tenant.connector_class(),
        config=dict(tenant.config),
        transport_override=tenant.transport_factory(fixtures_dir),
    )

    assert result.skipped_object_types == {}
    emitted = {obj.attributes.get("resource_type") for obj in result.normalized_objects if obj.kind == "resource"}
    assert emitted - VALID == set()
