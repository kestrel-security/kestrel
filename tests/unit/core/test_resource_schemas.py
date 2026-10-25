# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.policies.resource_schemas`: prompt/schema documentation and demo
fixtures used by AI-assisted policy drafting.

`FIXTURE_DEMOS` and `CONNECTOR_FIXTURE_DEMOS` are baked-in product content
(AI prompt scaffolding, not shipped connector/pack fixtures), so these tests
assert on structure and routing -- valid JSON, the right keys, the right
resource-type fallback -- never on the specific persona strings the demo
data happens to contain.
"""

from __future__ import annotations

import json

from kestrel.policies.resource_schemas import (
    RESOURCE_SCHEMAS,
    fixture_demo_for,
    schema_docs_for_prompt,
)


def test_schema_docs_for_a_known_resource_type_returns_only_that_schema():
    doc = schema_docs_for_prompt("event")

    assert doc == RESOURCE_SCHEMAS["event"]
    assert "grant" not in doc.split("\n", 1)[0]  # not the concatenated multi-schema block


def test_schema_docs_for_an_unknown_resource_type_falls_back_to_the_full_block():
    doc = schema_docs_for_prompt("not-a-real-resource-type")

    for resource_type in ("identity", "grant", "application", "tenant_setting", "event"):
        assert RESOURCE_SCHEMAS[resource_type] in doc


def test_schema_docs_with_no_resource_type_returns_the_full_block():
    doc = schema_docs_for_prompt(None)

    assert doc == schema_docs_for_prompt("not-a-real-resource-type")


def test_fixture_demo_for_returns_valid_json_with_the_documented_shape():
    for resource_type in ("identity", "grant", "tenant_setting", "event", "application"):
        payload = json.loads(fixture_demo_for(resource_type))
        assert "rows" in payload
        assert "expected_match_subject_ids" in payload
        assert isinstance(payload["rows"], list)
        assert isinstance(payload["expected_match_subject_ids"], list)


def test_fixture_demo_for_an_unknown_resource_type_falls_back_to_identity():
    assert fixture_demo_for("not-a-real-resource-type") == fixture_demo_for("identity")


def test_fixture_demo_for_none_falls_back_to_identity():
    assert fixture_demo_for(None) == fixture_demo_for("identity")


def test_fixture_demo_for_a_connector_hint_with_an_override_differs_from_the_generic_demo():
    # okta has connector-specific overrides for identity/tenant_setting/event.
    generic = fixture_demo_for("identity", connector_hint=None)
    okta_specific = fixture_demo_for("identity", connector_hint="okta")

    assert okta_specific != generic
    payload = json.loads(okta_specific)
    assert "rows" in payload


def test_fixture_demo_for_a_connector_without_an_override_uses_the_generic_demo():
    # "grant" has no okta-specific override in CONNECTOR_FIXTURE_DEMOS.
    assert fixture_demo_for("grant", connector_hint="okta") == fixture_demo_for("grant", connector_hint=None)


def test_fixture_demo_for_an_unknown_connector_hint_uses_the_generic_demo():
    assert fixture_demo_for("identity", connector_hint="not-a-real-connector") == fixture_demo_for(
        "identity", connector_hint=None
    )
