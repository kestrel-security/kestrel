# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- worker type resolution from connector facts and operator rules."""

from __future__ import annotations

import pytest
from kestrel.identities.classification import (
    AccountFacts,
    ClassificationRuleError,
    RuleSpec,
    resolve_worker_type,
    rule_matches,
    validate_rule,
)

pytestmark = pytest.mark.unit


def _facts(**overrides) -> AccountFacts:
    base = {
        "email": "pat@vendor.example",
        "application_type": "google_workspace",
        "org_unit_path": "/Contractors/EMEA",
        "user_type": None,
        "group_names": ["contractors-emea"],
        "connector_worker_type": "unknown",
    }
    base.update(overrides)
    return AccountFacts(**base)


def _rule(**overrides) -> RuleSpec:
    base = {"worker_type": "contractor", "match_kind": "email_domain", "match_value": "vendor.example"}
    base.update(overrides)
    return validate_rule(RuleSpec(**base))


@pytest.mark.parametrize(
    ("rule", "facts", "expected"),
    [
        ({"match_kind": "email_domain", "match_value": "vendor.example"}, {"email": "pat@vendor.example"}, True),
        ({"match_kind": "email_domain", "match_value": "vendor.example"}, {"email": "pat@eu.vendor.example"}, True),
        ({"match_kind": "email_domain", "match_value": "vendor.example"}, {"email": "pat@notvendor.example"}, False),
        ({"match_kind": "email_domain", "match_value": "vendor.example"}, {"email": None}, False),
        ({"match_kind": "org_unit_path_prefix", "match_value": "/Contractors"}, {"org_unit_path": "/Contractors"}, True),
        (
            {"match_kind": "org_unit_path_prefix", "match_value": "/Contractors"},
            {"org_unit_path": "/Contractors/EMEA"},
            True,
        ),
        ({"match_kind": "org_unit_path_prefix", "match_value": "/Contractors"}, {"org_unit_path": "/ContractorsX"}, False),
        ({"match_kind": "org_unit_path_prefix", "match_value": "/"}, {"org_unit_path": "/Anything"}, True),
        ({"match_kind": "group_name", "match_value": "contractors*"}, {"group_names": ["Contractors-EMEA"]}, True),
        ({"match_kind": "group_name", "match_value": "contractors"}, {"group_names": ["Contractors-EMEA"]}, False),
        ({"match_kind": "user_type", "match_value": "contract*"}, {"user_type": "Contract Worker"}, True),
        ({"match_kind": "user_type", "match_value": "contract*"}, {"user_type": None}, False),
        ({"match_kind": "application_type", "match_value": "slack"}, {"application_type": "slack"}, True),
        ({"match_kind": "application_type", "match_value": "slack"}, {"application_type": "okta"}, False),
    ],
)
def test_rule_matches_per_kind(rule, facts, expected):
    assert rule_matches(_rule(**rule), _facts(**facts)) is expected


def test_a_disabled_rule_or_an_application_scope_mismatch_never_matches():
    assert rule_matches(_rule(is_enabled=False), _facts()) is False
    assert rule_matches(_rule(application_type="okta"), _facts(application_type="google_workspace")) is False
    assert rule_matches(_rule(application_type="google_workspace"), _facts()) is True


def test_the_first_matching_rule_wins_and_names_itself_as_the_source():
    import uuid

    first = _rule(worker_type="vendor_or_partner", id=uuid.UUID(int=1))
    second = _rule(
        worker_type="contractor", match_kind="org_unit_path_prefix", match_value="/Contractors", id=uuid.UUID(int=2)
    )

    assert resolve_worker_type([first, second], _facts()) == ("vendor_or_partner", f"rule:{uuid.UUID(int=1)}")
    assert resolve_worker_type([second, first], _facts()) == ("contractor", f"rule:{uuid.UUID(int=2)}")


def test_with_no_matching_rule_the_connector_value_stands():
    assert resolve_worker_type([], _facts(connector_worker_type="employee")) == ("employee", "connector")
    assert resolve_worker_type([], _facts(connector_worker_type="unknown")) == ("unknown", None)
    assert resolve_worker_type([_rule(match_value="other.example")], _facts(connector_worker_type="guest")) == (
        "guest",
        "connector",
    )


def test_rules_never_relabel_a_service_account():
    assert resolve_worker_type([_rule()], _facts(connector_worker_type="service")) == ("service", "connector")


@pytest.mark.parametrize(
    "bad",
    [
        {"worker_type": "unknown"},
        {"worker_type": "wizard"},
        {"match_kind": "shoe_size"},
        {"match_value": "   "},
        {"match_kind": "email_domain", "match_value": "not a domain"},
        {"match_kind": "org_unit_path_prefix", "match_value": "Contractors"},
    ],
)
def test_validate_rule_rejects_bad_input(bad):
    with pytest.raises(ClassificationRuleError):
        _rule(**bad)


def test_validate_rule_normalizes_values():
    rule = _rule(match_kind="email_domain", match_value=" @Vendor.Example ", label="  Vendors ")
    assert (rule.match_value, rule.label) == ("vendor.example", "Vendors")
    assert _rule(match_kind="org_unit_path_prefix", match_value="/Contractors/").match_value == "/Contractors"
