# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Cross-application drafts: the offline template for the headline intent, the
scope the prompt carries, the single-app guard repair, and two repair turns."""

from __future__ import annotations

from typing import Any

import pytest
from kestrel.policies import generate
from kestrel.policies.cross_app_fixtures import CONTRACTOR_DORMANT_IN_APP
from kestrel.policies.generate_catalog import INTENT_TEMPLATES, fixtures_for_intent, match_intent_template
from kestrel.policies.llm_settings import LlmCredentials
from kestrel.policies.packs import get_packs_dir
from kestrel.policies.probes import probe_policy, probe_rows
from kestrel.policies.testing import run_fixture_test_dict

from tests.unit.policies.test_generate_helper_contract import DEMO_INTENT
from tests.unit.policies.test_generate_intent import USER_INTENT

_CREDS = LlmCredentials(api_key="k", provider="openai", model="m", base_url="http://llm.invalid", source="env")

# Cross-application by wording, but no offline template covers guests, so the
# provider path runs. The pack's contractor fixtures become the (advisory)
# scaffold; the scope guard and REQUIRES checks are what the loop exercises.
NOVEL_INTENT = "Guests who hold an enabled account in any app but have not signed into that app for 30 days"

PACK_SOURCE = (get_packs_dir() / "cross-app" / "policies" / "cross_app_contractor_dormant_in_app.py").read_text()

# A plausible first draft for the user's intent: scoped to Okta (wrong), and
# reading last_active_at without the trust check.
SINGLE_APP_DRAFT = """POLICY_ID = "contractors-dormant"
TITLE = "Contractors dormant"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "d"
REMEDIATION = "r"

def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "okta":
        return True
    if worker_type_of(resource) != "contractor":
        return True
    return within_last_days(identity.get("last_active_at"), 30)

def evidence(resource):
    return {"identity.email": (resource.get("identity") or {}).get("email")}
"""


def _fake_chat(monkeypatch: pytest.MonkeyPatch, replies: list[str]) -> list[list[dict[str, str]]]:
    calls: list[list[dict[str, str]]] = []

    def fake_chat(*, messages: list[dict[str, str]], **_: Any) -> str:
        calls.append(messages)
        return replies[min(len(calls), len(replies)) - 1]

    monkeypatch.setattr(generate, "chat_completion", fake_chat)
    return calls


# -- templates and fixtures ---------------------------------------------------


def test_the_user_intent_routes_to_the_cross_app_template_however_it_is_hinted():
    for hint in (None, "okta", "cross_app"):
        template = match_intent_template(USER_INTENT, connector_hint=hint)
        assert template is not None, hint
        assert template.name == "cross-app-contractor-dormant-in-app", hint
    # The Okta-scoped demo intent still routes to its own fixtures, not the cross-app ones.
    assert match_intent_template(DEMO_INTENT, connector_hint="okta") is None
    assert fixtures_for_intent(DEMO_INTENT, connector_hint="okta", resource_type="identity") is not None
    assert fixtures_for_intent(USER_INTENT, connector_hint=None, resource_type="identity") is CONTRACTOR_DORMANT_IN_APP


def test_cross_app_templates_substitute_the_threshold_and_pass_their_fixtures():
    template = next(t for t in INTENT_TEMPLATES if t.name == "cross-app-contractor-dormant-in-app")
    source = template.source_factory("contractors not signed into any app for 45 days")
    assert "STALE_DAYS = 45" in source
    assert "cross-app-contractor-dormant-in-app" not in source  # POLICY_ID comes from the intent
    assert run_fixture_test_dict(source, dict(template.fixtures)).passed
    departed = next(t for t in INTENT_TEMPLATES if t.name == "cross-app-departed-account-outlived-offboarding")
    assert "GRACE_DAYS = 14" in departed.source_factory("still enabled 14 days after being disabled in Okta")


def test_offline_generate_of_the_user_intent_returns_the_template_with_scope_and_requires():
    draft = generate.generate_policy_draft(intent=USER_INTENT)
    assert draft["provider"] == "template"
    assert draft["scope"] == "cross_app"
    assert draft["requires"] == ["identity:last_sign_in", "identity:worker_type"]
    assert draft["intent_analysis"]["subject"]["worker_type"] == "contractor"
    assert draft["fixture_test"]["passed"] is True
    assert "advisory" not in draft["fixture_test"]
    assert draft["repair_turns"] == 0
    assert "STALE_DAYS = 30" in draft["source_text"]


def test_the_pack_policy_passes_every_cross_app_probe():
    result = probe_policy(PACK_SOURCE, dict(CONTRACTOR_DORMANT_IN_APP))
    assert result is not None
    assert result["passed"], result["errors"]
    labels = list(probe_rows(CONTRACTOR_DORMANT_IN_APP["rows"][:1], "identity"))
    assert any("cluster.accounts[].last_active_at=missing" in label for label in labels)
    assert any(label.endswith("cluster-missing") for label in labels)
    assert any(label.endswith("cluster-accounts-empty") for label in labels)
    assert any(label.endswith("worker-type-unknown") for label in labels)


def test_a_draft_that_indexes_the_first_account_crashes_on_the_empty_cluster_probe():
    source = PACK_SOURCE.replace(
        "    status = activity_status(resource, STALE_DAYS)\n",
        '    first = (resource.get("cluster") or {})["accounts"][0]\n    status = activity_status(resource, STALE_DAYS)\n',
    )
    result = probe_policy(source, dict(CONTRACTOR_DORMANT_IN_APP))
    assert result is not None
    assert not result["passed"]
    # The sparse, cluster-missing and empty-accounts probes all expose it; any one is enough.
    assert "IndexError" in result["errors"][0]


# -- the generation loop ----------------------------------------------------------


def test_a_single_app_guard_in_a_cross_app_draft_is_repaired(monkeypatch: pytest.MonkeyPatch):
    calls = _fake_chat(monkeypatch, [SINGLE_APP_DRAFT, PACK_SOURCE])
    # Hint Okta: the operator picked their IdP, the wording still says "any app".
    draft = generate.generate_policy_draft(intent=NOVEL_INTENT, connector_hint="okta", credentials=_CREDS)

    assert len(calls) == 2
    system = calls[0][0]["content"]
    assert "Cross-application policies" in system
    assert "Shipped cross-application policies" in system
    user = calls[0][-1]["content"]
    assert "Plan (from intent analysis" in user
    assert "scope: cross_app" in user
    repair_user = calls[1][-1]["content"]
    assert "returns early on the application type" in repair_user
    assert draft["scope"] == "cross_app"
    assert draft["repair_turns"] == 1
    assert "scope_errors" not in draft
    assert draft["fixture_test"]["passed"] is True
    assert draft["fixture_test"]["advisory"] is True
    assert 'REQUIRES = ["identity:worker_type", "identity:last_sign_in"]' in draft["source_text"]


def test_two_repair_turns_then_stop(monkeypatch: pytest.MonkeyPatch):
    calls = _fake_chat(monkeypatch, [SINGLE_APP_DRAFT, SINGLE_APP_DRAFT.replace("okta", "slack"), PACK_SOURCE])
    draft = generate.generate_policy_draft(intent=NOVEL_INTENT, credentials=_CREDS)
    assert len(calls) == 3
    assert draft["repair_turns"] == 2
    assert draft["fixture_test"]["passed"] is True


def test_a_repair_that_returns_the_same_source_stops_early(monkeypatch: pytest.MonkeyPatch):
    calls = _fake_chat(monkeypatch, [SINGLE_APP_DRAFT, SINGLE_APP_DRAFT])
    draft = generate.generate_policy_draft(intent=NOVEL_INTENT, credentials=_CREDS)
    assert len(calls) == 2
    assert draft["repair_turns"] == 1
    assert draft["scope_errors"]


def test_requires_is_declared_on_a_model_draft_that_forgot_it(monkeypatch: pytest.MonkeyPatch):
    without = "\n".join(line for line in PACK_SOURCE.splitlines() if not line.startswith("REQUIRES")) + "\n"
    _fake_chat(monkeypatch, [without])
    draft = generate.generate_policy_draft(intent=NOVEL_INTENT, credentials=_CREDS)
    assert 'REQUIRES = ["identity:last_sign_in", "identity:worker_type"]' in draft["source_text"]
    assert draft["validation"]["valid"] is True
    assert draft["repair_turns"] == 0


def test_single_app_drafts_are_unchanged_by_the_cross_app_machinery(monkeypatch: pytest.MonkeyPatch):
    from tests.unit.policies.test_generate_helper_contract import CORRECTED_DRAFT

    _fake_chat(monkeypatch, [CORRECTED_DRAFT])
    draft = generate.generate_policy_draft(intent=DEMO_INTENT, connector_hint="okta", credentials=_CREDS)
    assert draft["scope"] == "single_app"
    assert draft["source_text"] == CORRECTED_DRAFT
    assert draft["requires"] == []
    assert draft["repair_turns"] == 0


def test_assigned_role_intent_still_reaches_the_okta_template_offline():
    draft = generate.generate_policy_draft(
        intent="Okta users assigned the super admin role without MFA", connector_hint="okta", scope="single_app"
    )
    assert draft["provider"] == "template"
    assert 'RESOURCE_TYPE = "identity"' in draft["source_text"]


def test_a_setting_draft_in_a_cross_app_request_is_not_sent_back_for_its_app_guard(monkeypatch: pytest.MonkeyPatch):
    setting_draft = """POLICY_ID = "slack-sso"
TITLE = "t"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "d"
REMEDIATION = "r"

def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "slack":
        return True
    if setting.get("key") != "sso_required":
        return True
    return setting.get("value") is not False

def evidence(resource):
    return {}
"""
    calls = _fake_chat(monkeypatch, [setting_draft])
    draft = generate.generate_policy_draft(intent="SSO not enforced in any app", scope="cross_app", credentials=_CREDS)
    assert len(calls) == 1
    assert "scope_errors" not in draft
    assert "REQUIRES" not in draft["source_text"]
