# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Scope and intent analysis: deterministic, provider-free, and the reason a
cross-application intent never lands on a single-application template."""

from __future__ import annotations

import pytest
from kestrel.policies.generate_intent import (
    SCOPE_CROSS_APP,
    SCOPE_SINGLE_APP,
    analyze_intent,
    declared_requires,
    ensure_requires,
    normalize_connector_hint,
    render_plan,
    resolve_scope,
    single_app_guard,
)

from tests.unit.policies.test_generate_helper_contract import DEMO_INTENT

USER_INTENT = (
    "Identify contractors who have an account that's active in any app but haven't signed into that app in the last 30 days"
)


@pytest.mark.parametrize(
    ("intent", "hint", "expected_scope", "expected_focus"),
    [
        (USER_INTENT, None, SCOPE_CROSS_APP, None),
        (USER_INTENT, "okta", SCOPE_CROSS_APP, "okta"),  # strong wording wins; Okta becomes the focus
        (USER_INTENT, "cross_app", SCOPE_CROSS_APP, None),
        (DEMO_INTENT, "okta", SCOPE_SINGLE_APP, "okta"),
        (DEMO_INTENT, None, SCOPE_SINGLE_APP, "okta"),  # names Okta, so weak wording does not flip it
        ("contractors who have not signed in for 30 days", None, SCOPE_CROSS_APP, None),  # weak, unhinted
        ("contractors who have not signed in for 30 days", "slack", SCOPE_SINGLE_APP, "slack"),
        ("Okta admins without MFA", None, SCOPE_SINGLE_APP, "okta"),
        ("Admins in any connected app whose identity provider account has no MFA", None, SCOPE_CROSS_APP, None),
        ("GitHub repos without branch protection", "github", SCOPE_SINGLE_APP, "github"),
        ("Separation of duties between Okta and GitHub admins", None, SCOPE_CROSS_APP, "okta"),
    ],
)
def test_resolve_scope(intent, hint, expected_scope, expected_focus):
    resolution = resolve_scope(intent, connector_hint=hint)
    assert (resolution.scope, resolution.focus_connector) == (expected_scope, expected_focus)


def test_an_explicit_scope_outranks_wording():
    assert resolve_scope(USER_INTENT, connector_hint="okta", scope=SCOPE_SINGLE_APP).scope == SCOPE_SINGLE_APP
    assert resolve_scope("Okta admins without MFA", scope=SCOPE_CROSS_APP).scope == SCOPE_CROSS_APP


def test_connector_hint_aliases():
    assert normalize_connector_hint("All apps") == "cross_app"
    assert normalize_connector_hint("cross-app") == "cross_app"
    assert normalize_connector_hint("Google") == "google_workspace"
    assert normalize_connector_hint("IdP") == "okta"
    assert normalize_connector_hint(None) is None


def test_analysis_of_the_user_intent_names_the_fields_and_capabilities():
    analysis = analyze_intent(USER_INTENT)
    assert analysis.scope == SCOPE_CROSS_APP
    assert analysis.subject["worker_type"] == "contractor"
    assert "stale_activity" in analysis.conditions
    assert analysis.days == 30
    assert analysis.per == "account"
    assert "cluster.accounts[].last_active_at" in analysis.fields_needed
    assert analysis.requires == ["identity:last_sign_in", "identity:worker_type"]
    plan = render_plan(analysis)
    assert "REQUIRES = ['identity:last_sign_in', 'identity:worker_type']" in plan
    assert "threshold: 30 days" in plan
    assert "unknown" in plan


def test_analysis_reads_per_person_and_event_intents():
    person = analyze_intent("People with enabled accounts who have been inactive in every app for 3 months")
    assert person.per == "person"
    assert person.days == 90
    event = analyze_intent("Admin privilege granted in any app to a user who was disabled in the identity provider")
    assert event.resource_type == "event"
    assert "privilege_event" in event.conditions
    assert analyze_intent("Okta admins without MFA").requires == []


def test_ensure_requires_inserts_or_merges():
    source = 'POLICY_ID = "x"\nRESOURCE_TYPE = "identity"\n\ndef policy(resource):\n    return True\n'
    with_keys = ensure_requires(source, ["identity:last_sign_in"])
    assert 'RESOURCE_TYPE = "identity"\nREQUIRES = ["identity:last_sign_in"]\n' in with_keys
    merged = ensure_requires(with_keys, ["identity:worker_type", "identity:last_sign_in"])
    assert declared_requires(merged) == ["identity:last_sign_in", "identity:worker_type"]
    assert ensure_requires(merged, ["identity:worker_type"]) == merged
    assert ensure_requires(source, []) == source
    assert ensure_requires("def policy(resource):\n    return True\n", ["identity:groups"]).startswith("def policy")


def test_single_app_guard_spots_the_idiom():
    assert single_app_guard('    if application.get("type") != "okta":\n        return True\n') is not None
    assert single_app_guard('    if application.get("type") not in ("okta", "slack"):\n') is not None
    assert single_app_guard("    if not application_matches(resource, ['custom']):\n") is not None
    assert single_app_guard('    if application.get("type") in cluster.get("idp_application_types"):\n') is None


@pytest.mark.parametrize(
    ("intent", "hint"),
    [
        ("Slack workspace does not enforce SSO through the identity provider", "slack"),
        ("Slack channels shared across workspaces", "slack"),
        ("GitHub org allows members to install any app", "github"),
        ("Okta IdP discovery rules that route to a personal IdP", "okta"),
        ("GitHub secret scanning disabled across repositories", "github"),
    ],
)
def test_single_app_intents_with_a_hint_stay_single_app(intent, hint):
    assert resolve_scope(intent, connector_hint=hint).scope == SCOPE_SINGLE_APP


def test_contextual_wording_still_means_cross_app_without_a_hint():
    assert resolve_scope("People disabled in the identity provider who still have accounts").scope == SCOPE_CROSS_APP


def test_an_identity_intent_about_assigned_roles_is_not_an_event_policy():
    analysis = analyze_intent("Okta users assigned the super admin role without MFA", connector_hint="okta")
    assert analysis.resource_type is None
    event = analyze_intent("Alert when admin privilege is granted to a user disabled in the identity provider")
    assert event.resource_type == "event"
