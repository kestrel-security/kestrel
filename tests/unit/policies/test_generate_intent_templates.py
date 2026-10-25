# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Intent templates and the fixture pairs an AI draft is tested against.

A draft is only as trustworthy as its fixture test. The generic identity
pairs must carry every field the common posture intents read, or a correct
policy fails its own test (a dormancy policy over rows with no
``last_active_at`` flags both admins) and the repair pass is pushed to
"fix" a policy that was right.
"""

from __future__ import annotations

import json

import pytest
from kestrel.policies.generate_catalog import INTENT_TEMPLATES, match_intent_template
from kestrel.policies.resource_schemas import fixture_demo_for
from kestrel.policies.testing import run_fixture_test_dict


@pytest.mark.parametrize(
    ("intent", "expected"),
    [
        ("Detect Okta admin that has not signed in within last 90 days", "okta-dormant-admin"),
        ("Okta admins who have not logged in for 60 days", "okta-dormant-admin"),
        ("Okta privileged users with no login activity", "okta-dormant-admin"),
        ("Okta administrators that haven't signed in recently", "okta-dormant-admin"),
        ("dormant okta admins", "okta-dormant-admin"),
        ("Okta admins without MFA", "okta-admin-without-mfa"),
        ("Detect Okta admin accounts missing mfa", "okta-admin-without-mfa"),
        ("disabled okta super admins still privileged", "okta-disabled-privileged-admin"),
        ("weak okta password policy", "okta-password-policy-weak"),
    ],
)
def test_intent_phrasings_route_to_the_expected_template(intent: str, expected: str) -> None:
    matched = match_intent_template(intent, connector_hint="okta")
    assert matched is not None
    assert matched.name == expected
    # The same phrasing with no connector hint must not route somewhere else.
    unhinted = match_intent_template(intent)
    assert unhinted is None or unhinted.name == expected


def test_every_template_passes_its_own_fixtures() -> None:
    for template in INTENT_TEMPLATES:
        result = run_fixture_test_dict(template.source_factory("Example intent"), dict(template.fixtures))
        assert result.passed, (template.name, result.missing, result.unexpected)


@pytest.mark.parametrize("connector_hint", ["okta", None])
def test_generic_identity_pair_carries_last_active_at(connector_hint: str | None) -> None:
    fixtures = json.loads(fixture_demo_for("identity", connector_hint))
    rows = fixtures["rows"]
    assert len(rows) == 2
    for row in rows:
        assert "last_active_at" in row["identity"], row["_subject_id"]
    (expected,) = fixtures["expected_match_subject_ids"]
    by_id = {row["_subject_id"]: row["identity"]["last_active_at"]["$days_ago"] for row in rows}
    # The expected match is the stale admin; the other row is recent.
    assert by_id[expected] > 90
    assert all(days < 90 for sid, days in by_id.items() if sid != expected)


def test_dormancy_policy_passes_against_the_generic_okta_pair() -> None:
    """The shape an LLM draft takes for 'admins not signed in for 90 days'
    must pass the generic Okta identity pair, not just the dormant template's own."""
    source = (
        'POLICY_ID = "okta-admins-inactive-90-days"\n'
        'TITLE = "Okta admins inactive for 90 days"\n'
        'SEVERITY = "high"\n'
        'RESOURCE_TYPE = "identity"\n'
        'DESCRIPTION = "Okta admins who have not signed in within 90 days."\n'
        'REMEDIATION = "Review the admin account."\n'
        "\n"
        "def policy(resource):\n"
        '    identity = resource.get("identity") or {}\n'
        '    if (resource.get("application") or {}).get("type") != "okta":\n'
        "        return True\n"
        '    if not resource.get("roles"):\n'
        "        return True\n"
        '    last_active_at = identity.get("last_active_at")\n'
        "    if last_active_at is None:\n"
        "        return False\n"
        "    return (time.time() - last_active_at.timestamp()) <= 90 * 86400\n"
        "\n"
        "def evidence(resource):\n"
        '    return {"identity.email": (resource.get("identity") or {}).get("email")}\n'
    )
    result = run_fixture_test_dict(source, json.loads(fixture_demo_for("identity", "okta")))
    assert result.passed, (result.missing, result.unexpected)
