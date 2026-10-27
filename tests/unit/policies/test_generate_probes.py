# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Edge-case probe rows and intent-aware fixtures for AI drafts.

Fixtures only run the branches their rows take, so a draft can pass them and
still crash on the first real row with a missing or naive timestamp. And when
the scaffold's expected matches were written for another intent, a fixture
failure says nothing about the draft and must not steer the repair turn.
"""

from __future__ import annotations

from typing import Any

import pytest
from kestrel.policies import generate
from kestrel.policies.generate_catalog import (
    OKTA_IDENTITY_FIXTURES,
    OKTA_STALE_EXTERNAL_FIXTURES,
    fixtures_for_intent,
)
from kestrel.policies.llm_settings import LlmCredentials
from kestrel.policies.probes import probe_policy, probe_rows
from kestrel.policies.testing import run_fixture_test_dict

from tests.unit.policies.test_generate_helper_contract import CORRECTED_DRAFT, DEMO_INTENT

_HEADER = """POLICY_ID = "probe-draft"
TITLE = "Probe draft"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "d"
REMEDIATION = "r"
"""

# Compiles, passes the stale-external fixtures (every timestamp there is an
# aware datetime), then raises TypeError on a naive or string timestamp.
NAIVE_COMPARE_DRAFT = (
    _HEADER
    + """

def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "okta":
        return True
    if identity.get("is_disabled") or not identity.get("is_external"):
        return True
    last = identity.get("last_active_at")
    if last is None:
        return False
    return last > now().replace(year=now().year - 1)
"""
)

# Reads a nested key without a default: fine on full rows, a crash on sparse
# ones (RestrictedPython's getattr guard turns None.endswith into None, so
# the call raises TypeError).
SPARSE_CRASH_DRAFT = (
    _HEADER
    + """

def policy(resource):
    return resource.get("identity").get("email").endswith("@acme.example.com")
"""
)

_CREDS = LlmCredentials(api_key="k", provider="openai", model="m", base_url="http://llm.invalid", source="env")


def _fixtures() -> dict[str, Any]:
    return generate.json.loads(generate.json.dumps(OKTA_STALE_EXTERNAL_FIXTURES))


# -- probe rows ----------------------------------------------------------------


def test_probe_rows_cover_each_timestamp_shape_another_app_and_sparse_rows() -> None:
    probes = probe_rows(
        [{"_subject_id": "a", "identity": {"email": "x@y.z", "is_external": True}, "roles": ["r"]}], "identity"
    )
    labels = list(probes)
    for shape in ("missing", "iso-string", "naive-datetime", "aware-datetime"):
        assert f"a with identity.last_active_at={shape}" in labels
        assert f"a with identity.created_at_source={shape}" in labels
    assert "a with other-application" in labels
    sparse = probes["a with sparse"]
    assert sparse["identity"] == {"email": None, "is_external": True}
    assert sparse["roles"] == []
    assert len({str(row["_subject_id"]) for row in probes.values()}) == len(probes)


def test_the_corrected_demo_draft_passes_its_fixtures_and_every_probe() -> None:
    assert run_fixture_test_dict(CORRECTED_DRAFT, _fixtures()).passed
    result = probe_policy(CORRECTED_DRAFT, _fixtures())
    assert result is not None
    assert result["passed"], result["errors"]
    assert result["probed"] > 20


def test_a_naive_timestamp_comparison_passes_fixtures_but_fails_a_probe() -> None:
    assert run_fixture_test_dict(NAIVE_COMPARE_DRAFT, _fixtures()).passed
    result = probe_policy(NAIVE_COMPARE_DRAFT, _fixtures())
    assert result is not None
    assert not result["passed"]
    (error,) = result["errors"]
    assert "TypeError" in error
    assert "identity.last_active_at=" in error


def test_a_crash_on_sparse_rows_names_the_probe() -> None:
    result = probe_policy(SPARSE_CRASH_DRAFT, _fixtures())
    assert result is not None
    assert not result["passed"]
    assert "TypeError" in result["errors"][0]
    assert "sparse" in result["errors"][0]


def test_probe_skips_source_that_does_not_compile() -> None:
    assert probe_policy("def policy(:", _fixtures()) is None


# -- intent-aware fixtures -----------------------------------------------------


def test_the_demo_intent_gets_fixtures_written_for_it() -> None:
    assert fixtures_for_intent(DEMO_INTENT, connector_hint="okta", resource_type="identity") is OKTA_STALE_EXTERNAL_FIXTURES
    # Unscoped intents would rightly match the fixtures' other-app row.
    assert fixtures_for_intent(DEMO_INTENT, connector_hint=None, resource_type="identity") is None
    assert fixtures_for_intent("Okta users with long display names", connector_hint="okta", resource_type=None) is None
    assert (
        fixtures_for_intent("okta admins without mfa", connector_hint="okta", resource_type="identity")
        is OKTA_IDENTITY_FIXTURES
    )


def test_stale_external_fixtures_reject_the_usual_mistakes() -> None:
    unscoped = CORRECTED_DRAFT.replace('    if application.get("type") != "okta":\n        return True\n', "")
    result = run_fixture_test_dict(unscoped, _fixtures())
    assert not result.passed
    assert result.unexpected == {"github-guest-id"}


# -- generate --------------------------------------------------------------------


def _fake_chat(monkeypatch: pytest.MonkeyPatch, replies: list[str]) -> list[list[dict[str, str]]]:
    calls: list[list[dict[str, str]]] = []

    def fake_chat(*, messages: list[dict[str, str]], **_: Any) -> str:
        calls.append(messages)
        return replies[min(len(calls), len(replies)) - 1]

    monkeypatch.setattr(generate, "chat_completion", fake_chat)
    return calls


def test_generate_repairs_a_draft_that_crashes_on_a_probe_row(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_chat(monkeypatch, [NAIVE_COMPARE_DRAFT, CORRECTED_DRAFT])
    draft = generate.generate_policy_draft(intent=DEMO_INTENT, connector_hint="okta", credentials=_CREDS)

    assert len(calls) == 2
    repair_user = calls[1][-1]["content"]
    assert "edge-case row failed" in repair_user
    assert "TypeError" in repair_user
    assert draft["source_text"] == CORRECTED_DRAFT
    assert draft["probe_test"]["passed"] is True
    assert draft["fixture_test"]["passed"] is True
    assert "advisory" not in draft["fixture_test"]


def test_a_generic_scaffold_mismatch_is_advisory_and_does_not_trigger_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    source = (
        _HEADER
        + """

def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "okta":
        return True
    return len(identity.get("display_name") or "") <= 40
"""
    )
    calls = _fake_chat(monkeypatch, [source])
    draft = generate.generate_policy_draft(
        intent="Okta users with display names over 40 characters", connector_hint="okta", credentials=_CREDS
    )

    assert len(calls) == 1, "an advisory fixture failure must not start a repair turn"
    assert draft["validation"]["valid"] is True
    assert draft["fixture_test"]["passed"] is False
    assert draft["fixture_test"]["advisory"] is True
    assert draft["probe_test"]["passed"] is True


def test_templates_are_not_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_chat(monkeypatch, ["unused"])
    draft = generate.generate_policy_draft(intent="okta admins without mfa", connector_hint="okta")
    assert draft["provider"] == "template"
    assert draft["probe_test"] is None
