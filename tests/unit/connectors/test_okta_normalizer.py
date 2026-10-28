# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`OktaNormalizer`: pure `RawObject -> NormalizedObject` mapping, built from
hand-written payloads only (see the fixture-contract rule in
`test_connector_fixture_contract.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.connectors.sdk.base import RawObject
from kestrel_connector_okta.normalizer import (
    OktaNormalizer,
    _first_user_target,
    _is_sensitive_scope,
    _kestrel_action_for_okta_event,
    _mfa_enroll_policy_required,
    _parse_dt,
    _threat_insight_enabled,
)

_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _raw(object_type: str, provider_id: str, payload: dict) -> RawObject:
    return RawObject(object_type=object_type, provider_id=provider_id, payload=payload, collected_at=_NOW)


def test_normalize_raises_for_an_unknown_object_type():
    with pytest.raises(ValueError, match="widget"):
        OktaNormalizer().normalize("widget", _raw("widget", "1", {}))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("not-a-date", None),
        ("2026-07-01T12:00:00Z", datetime(2026, 7, 1, 12, 0, tzinfo=UTC)),
        ("2026-07-01T12:00:00+00:00", datetime(2026, 7, 1, 12, 0, tzinfo=UTC)),
        (datetime(2026, 7, 1, 12, 0), datetime(2026, 7, 1, 12, 0, tzinfo=UTC)),
        (datetime(2026, 7, 1, 12, 0, tzinfo=UTC), datetime(2026, 7, 1, 12, 0, tzinfo=UTC)),
    ],
)
def test_parse_dt(value, expected):
    assert _parse_dt(value) == expected


def test_is_sensitive_scope_matches_the_curated_set_and_the_okta_prefix():
    assert _is_sensitive_scope("okta.users.manage") is True
    assert _is_sensitive_scope("okta.some.future.scope") is True
    assert _is_sensitive_scope("profile") is True
    assert _is_sensitive_scope("some.other.scope") is False


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("none", False),
        ("disabled", False),
        ("off", False),
        ("NONE", False),
        ("audit", True),
        ("block", True),
    ],
)
def test_threat_insight_enabled(action, expected):
    assert _threat_insight_enabled({"action": action}) is expected


def test_threat_insight_enabled_is_none_when_action_key_absent():
    assert _threat_insight_enabled({}) is None


def test_mfa_enroll_policy_required_false_for_inactive_policy():
    assert _mfa_enroll_policy_required({"status": "INACTIVE", "settings": {}}) is False


def test_mfa_enroll_policy_required_none_when_active_but_no_factors_declared():
    assert _mfa_enroll_policy_required({"status": "ACTIVE", "settings": {}}) is None


def test_mfa_enroll_policy_required_true_when_any_factor_is_required():
    payload = {
        "status": "ACTIVE",
        "settings": {"factors": {"okta_verify": {"enroll": {"self": "REQUIRED"}}, "sms": {"enroll": {"self": "OPTIONAL"}}}},
    }
    assert _mfa_enroll_policy_required(payload) is True


def test_mfa_enroll_policy_required_false_when_no_factor_is_required():
    payload = {
        "status": "ACTIVE",
        "settings": {"factors": {"sms": {"enroll": {"self": "OPTIONAL"}}}},
    }
    assert _mfa_enroll_policy_required(payload) is False


def test_first_user_target_prefers_a_user_typed_target_over_others():
    targets = [{"type": "AppInstance", "id": "app-1"}, {"type": "User", "id": "user-1"}]

    assert _first_user_target({"target": targets})["id"] == "user-1"


def test_first_user_target_falls_back_to_the_first_target_when_no_user_typed_one_exists():
    targets = [{"type": "AppInstance", "id": "app-1"}]

    assert _first_user_target({"target": targets})["id"] == "app-1"


def test_first_user_target_returns_none_when_target_is_missing_or_not_a_list():
    assert _first_user_target({}) is None
    assert _first_user_target({"target": "not-a-list"}) is None
    assert _first_user_target({"target": []}) is None


def test_kestrel_action_for_okta_event_maps_known_types_and_drops_others():
    assert _kestrel_action_for_okta_event({"eventType": "user.mfa.factor.deactivate"}) == "mfa.disable"
    assert _kestrel_action_for_okta_event({"eventType": "user.session.start"}) is None
    assert _kestrel_action_for_okta_event({}) is None


def test_user_service_account_detected_by_clients_okta_com_login_suffix():
    normalizer = OktaNormalizer()
    service_raw = _raw("user", "1", {"id": 1, "status": "ACTIVE", "profile": {"login": "svc@clients.okta.com"}})
    human_raw = _raw("user", "2", {"id": 2, "status": "ACTIVE", "profile": {"login": "person@example.com"}})

    assert normalizer.normalize("user", service_raw)[0].attributes["identity_type"] == "service_account"
    assert normalizer.normalize("user", human_raw)[0].attributes["identity_type"] == "user"


@pytest.mark.parametrize(
    ("status", "expected_disabled"),
    [("ACTIVE", False), ("DEPROVISIONED", True), ("SUSPENDED", True), ("STAGED", False)],
)
def test_user_is_disabled_for_deprovisioned_or_suspended_status(status, expected_disabled):
    raw = _raw("user", "1", {"id": 1, "status": status, "profile": {"login": "x@example.com"}})

    identity = OktaNormalizer().normalize("user", raw)[0]

    assert identity.attributes["is_disabled"] is expected_disabled


def test_role_assignment_via_group_sets_inherited_access_path_and_source_group():
    raw = _raw(
        "role_assignment",
        "1",
        {"role_id": "r1", "user_id": "u1", "assignment_type": "GROUP", "group_id": "g1"},
    )

    grant = OktaNormalizer().normalize("role_assignment", raw)[0]

    assert grant.attributes["granted_via"] == "group"
    assert grant.attributes["source_group_ref"] == "g1"
    assert grant.relationships[0].access_path == "inherited_group"


def test_role_assignment_direct_has_no_source_group():
    raw = _raw("role_assignment", "1", {"role_id": "r1", "user_id": "u1"})

    grant = OktaNormalizer().normalize("role_assignment", raw)[0]

    assert grant.attributes["granted_via"] == "direct"
    assert "source_group_ref" not in grant.attributes
    assert grant.relationships[0].access_path == "direct"


def test_system_log_event_with_no_mapped_action_emits_nothing():
    raw = _raw("system_log", "evt-1", {"eventType": "user.session.start"})

    assert OktaNormalizer().normalize("system_log", raw) == []


def test_system_log_event_with_a_mapped_action_carries_actor_and_target():
    raw = _raw(
        "system_log",
        "evt-2",
        {
            "eventType": "user.mfa.factor.deactivate",
            "actor": {"id": "actor-1", "alternateId": "actor@example.com"},
            "target": [{"type": "User", "id": "target-1", "alternateId": "target@example.com"}],
            "published": "2026-07-01T00:00:00.000Z",
        },
    )

    event = OktaNormalizer().normalize("system_log", raw)[0]

    assert event.attributes["action"] == "mfa.disable"
    assert event.attributes["actor_provider_id"] == "actor-1"
    assert event.attributes["target_provider_id"] == "target-1"
    assert event.attributes["target_email"] == "target@example.com"


def test_mfa_enroll_policy_with_no_required_factor_emits_no_setting():
    raw = _raw("mfa_enroll_policy", "p1", {"status": "ACTIVE", "settings": {}})

    assert OktaNormalizer().normalize("mfa_enroll_policy", raw) == []


# -- authentication and session policy surface ---------------------


def _policy_raw(object_type: str, policy_id: str, rules: list[dict], **policy) -> RawObject:
    payload = {"id": policy_id, "name": "Test policy", "status": "ACTIVE", **policy, "rules": rules}
    return RawObject(
        object_type=object_type,
        provider_id=policy_id,
        payload=payload,
        collected_at=datetime(2026, 8, 1, tzinfo=UTC),
    )


def _signon_rule(*, status="ACTIVE", lifetime=480, idle=60, require_factor=True, name="rule"):
    return {
        "id": f"0pr{name}",
        "name": name,
        "status": status,
        "priority": 1,
        "actions": {
            "signon": {
                "requireFactor": require_factor,
                "session": {
                    "maxSessionLifetimeMinutes": lifetime,
                    "maxSessionIdleMinutes": idle,
                },
            }
        },
    }


def test_a_policy_carries_its_rules_not_just_its_name():
    """Okta policies are containers; Kestrel read only the container."""
    raw = _policy_raw("sign_on_policy", "00pglobal1", [_signon_rule()])

    value = OktaNormalizer().normalize("sign_on_policy", raw)[0].attributes["value"]

    assert value["rule_count"] == 1
    assert value["active_rule_count"] == 1
    assert value["rules"][0]["requires_mfa"] is True


def test_a_zero_minute_session_is_reported_as_unlimited_not_as_zero():
    # Okta encodes "no limit" as 0, so a naive reading of this field says a
    # session expires immediately when in fact it never does.
    raw = _policy_raw("sign_on_policy", "00pglobal1", [_signon_rule(lifetime=0, idle=0)])

    value = OktaNormalizer().normalize("sign_on_policy", raw)[0].attributes["value"]

    assert value["any_rule_unlimited_session"] is True
    assert value["rules"][0]["session"]["unlimited_lifetime"] is True


def test_the_rollup_reports_the_weakest_active_rule():
    # An attacker gets whichever rule is loosest, so that is what rolls up.
    raw = _policy_raw(
        "sign_on_policy",
        "00pglobal1",
        [
            _signon_rule(name="strict", require_factor=True, lifetime=60),
            _signon_rule(name="loose", require_factor=False, lifetime=0),
        ],
    )

    value = OktaNormalizer().normalize("sign_on_policy", raw)[0].attributes["value"]

    assert value["any_rule_without_mfa"] is True
    assert value["any_rule_unlimited_session"] is True


def test_an_inactive_rule_does_not_make_a_policy_look_permissive():
    raw = _policy_raw(
        "sign_on_policy",
        "00pglobal1",
        [
            _signon_rule(name="strict", require_factor=True, lifetime=60),
            _signon_rule(name="legacy", status="INACTIVE", require_factor=False, lifetime=0),
        ],
    )

    value = OktaNormalizer().normalize("sign_on_policy", raw)[0].attributes["value"]

    assert value["rule_count"] == 2
    assert value["active_rule_count"] == 1
    assert value["any_rule_without_mfa"] is False
    assert value["any_rule_unlimited_session"] is False


def test_a_rule_that_says_nothing_about_mfa_is_unknown_not_false():
    raw = _policy_raw(
        "access_policy",
        "00paccess1",
        [{"id": "0pr1", "name": "r", "status": "ACTIVE", "actions": {}}],
    )

    value = OktaNormalizer().normalize("access_policy", raw)[0].attributes["value"]

    assert value["rules"][0]["requires_mfa"] is None
    assert value["any_rule_without_mfa"] is False


def test_a_network_zone_condition_survives_normalization():
    rule = _signon_rule()
    rule["conditions"] = {"network": {"connection": "ZONE", "include": ["nzo1"]}}
    raw = _policy_raw("sign_on_policy", "00pglobal1", [rule])

    value = OktaNormalizer().normalize("sign_on_policy", raw)[0].attributes["value"]

    assert value["rules"][0]["network"]["connection"] == "ZONE"
    assert value["rules"][0]["network"]["zones_included"] == ["nzo1"]


def test_a_policy_with_no_rules_reports_none_rather_than_guessing():
    raw = _policy_raw("access_policy", "00paccess1", [])

    value = OktaNormalizer().normalize("access_policy", raw)[0].attributes["value"]

    assert value["active_rule_count"] == 0
    assert value["longest_session_minutes"] is None
    assert value["any_rule_without_mfa"] is False


def test_phishing_resistance_is_a_property_of_the_authenticator_not_of_having_mfa():
    """Push and OTP are relayable by an AiTM proxy; WebAuthn is not."""
    webauthn = RawObject(
        object_type="authenticator",
        provider_id="webauthn",
        payload={"key": "webauthn", "name": "Security Key", "status": "ACTIVE"},
        collected_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    push = RawObject(
        object_type="authenticator",
        provider_id="okta_verify",
        payload={"key": "okta_verify", "name": "Okta Verify", "status": "ACTIVE"},
        collected_at=datetime(2026, 8, 1, tzinfo=UTC),
    )

    assert OktaNormalizer().normalize("authenticator", webauthn)[0].attributes["value"]["phishing_resistant"] is True
    assert OktaNormalizer().normalize("authenticator", push)[0].attributes["value"]["phishing_resistant"] is False


# -- perimeter and automation surface ------------------------------


def _perimeter_raw(object_type: str, provider_id: str, payload: dict) -> RawObject:
    return RawObject(
        object_type=object_type,
        provider_id=provider_id,
        payload=payload,
        collected_at=_NOW,
    )


def test_a_policy_zone_admitting_the_whole_internet_is_flagged():
    """A zone containing 0.0.0.0/0 reads as a network control and is not one."""
    everywhere = _perimeter_raw(
        "network_zone",
        "nzo1",
        {"name": "LegacyAnywhere", "usage": "POLICY", "gateways": [{"type": "CIDR", "value": "0.0.0.0/0"}]},
    )
    office = _perimeter_raw(
        "network_zone",
        "nzo2",
        {"name": "Office", "usage": "POLICY", "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}]},
    )

    assert OktaNormalizer().normalize("network_zone", everywhere)[0].attributes["value"]["matches_everything"] is True
    assert OktaNormalizer().normalize("network_zone", office)[0].attributes["value"]["matches_everything"] is False


def test_an_ipv6_wildcard_zone_counts_too():
    raw = _perimeter_raw("network_zone", "nzo3", {"gateways": [{"type": "CIDR", "value": "::/0"}]})
    assert OktaNormalizer().normalize("network_zone", raw)[0].attributes["value"]["matches_everything"] is True


def test_a_plaintext_trusted_origin_is_flagged_because_it_can_receive_a_token():
    insecure = _perimeter_raw(
        "trusted_origin",
        "tos1",
        {"name": "Legacy", "origin": "http://legacy.example.test", "scopes": [{"type": "REDIRECT"}]},
    )
    secure = _perimeter_raw(
        "trusted_origin",
        "tos2",
        {"name": "App", "origin": "https://app.example.test", "scopes": [{"type": "REDIRECT"}]},
    )

    assert OktaNormalizer().normalize("trusted_origin", insecure)[0].attributes["value"]["insecure_scheme"] is True
    value = OktaNormalizer().normalize("trusted_origin", secure)[0].attributes["value"]
    assert value["insecure_scheme"] is False
    assert value["scopes"] == ["REDIRECT"]


def test_a_hook_setting_keeps_the_host_and_never_the_url():
    raw = _perimeter_raw(
        "inline_hook",
        "cal1",
        {
            "name": "Password import",
            "status": "ACTIVE",
            "channel": {"config": {"uri_host": "legacy-auth.example.test", "uri_scheme": "http"}},
        },
    )

    value = OktaNormalizer().normalize("inline_hook", raw)[0].attributes["value"]

    assert value["host"] == "legacy-auth.example.test"
    assert value["insecure_scheme"] is True


def test_an_identity_provider_that_auto_provisions_is_called_out():
    """JIT provisioning means a successful assertion creates an account."""
    auto = _perimeter_raw(
        "identity_provider",
        "idp1",
        {"name": "Partner", "type": "SAML2", "policy": {"provisioning": {"action": "AUTO"}}},
    )
    manual = _perimeter_raw(
        "identity_provider",
        "idp2",
        {"name": "Partner", "type": "SAML2", "policy": {"provisioning": {"action": "DISABLED"}}},
    )

    assert OktaNormalizer().normalize("identity_provider", auto)[0].attributes["value"]["auto_provisions_users"] is True
    assert OktaNormalizer().normalize("identity_provider", manual)[0].attributes["value"]["auto_provisions_users"] is False


def test_a_group_rule_records_its_expression_and_target_groups():
    raw = _perimeter_raw(
        "group_rule",
        "0pr1",
        {
            "name": "Contractors to Engineering",
            "status": "ACTIVE",
            "conditions": {"expression": {"value": 'user.userType=="Contractor"'}},
            "actions": {"assignUserToGroups": {"groupIds": ["00g1", "00g2"]}},
        },
    )

    value = OktaNormalizer().normalize("group_rule", raw)[0].attributes["value"]

    assert value["expression"] == 'user.userType=="Contractor"'
    assert value["assigns_to_group_ids"] == ["00g1", "00g2"]


def test_okta_app_kind_reflects_sign_on_mode_and_service_integrations():
    from kestrel_connector_okta.normalizer import OktaNormalizer

    def kind(payload):
        raw = RawObject(object_type="app", provider_id="0oa", payload=payload, collected_at=_NOW)
        return OktaNormalizer().normalize("app", raw)[0].attributes

    assert kind({"label": "HR", "signOnMode": "SAML_2_0"})["app_kind"] == "saml"
    assert kind({"label": "Legacy", "signOnMode": "BOOKMARK"})["app_kind"] == "bookmark"
    assert kind({"label": "Old", "signOnMode": "BROWSER_PLUGIN"})["app_kind"] == "swa"
    web = kind(
        {
            "label": "Slack",
            "signOnMode": "OPENID_CONNECT",
            "settings": {"oauthClient": {"grant_types": ["authorization_code"]}},
        }
    )
    assert (web["app_kind"], web["is_service_app"]) == ("oidc", False)
    svc = kind(
        {
            "label": "CI",
            "signOnMode": "OPENID_CONNECT",
            "settings": {"oauthClient": {"application_type": "service", "grant_types": ["client_credentials"]}},
        }
    )
    assert (svc["app_kind"], svc["is_service_app"]) == ("service", True)


# `GET /api/v1/org` is the Org Settings resource -- company name, contact,
# address, status. It carries no security configuration. `_normalize_org` used
# to derive `mfa_enroll_required` from it with a `setdefault` whose fallback was
# `bool(None or None)`, so every live tenant got a confident `False` for a field
# Okta never returned, and `okta-mfa-enroll-not-required` (high) opened on all
# of them. MFA enrollment comes from the MFA_ENROLL policy instead.
_REAL_ORG_PAYLOAD = {
    "id": "00o1",
    "subdomain": "acme",
    "companyName": "Acme Corp",
    "website": "https://acme.example.com",
    "status": "ACTIVE",
    "created": "2020-01-01T00:00:00.000Z",
    "lastUpdated": "2026-01-01T00:00:00.000Z",
}


def test_org_settings_carry_no_security_configuration():
    settings = OktaNormalizer().normalize("org", _raw("org", "00o1", dict(_REAL_ORG_PAYLOAD)))
    keys = {o.attributes["key"] for o in settings}
    assert keys == {"subdomain"}


def test_org_never_asserts_mfa_enrollment_it_did_not_read():
    """The regression: absence must not become a confident False."""
    settings = OktaNormalizer().normalize("org", _raw("org", "00o1", dict(_REAL_ORG_PAYLOAD)))
    for setting in settings:
        assert setting.attributes["key"] != "mfa_enroll_required"


def test_mfa_enrollment_comes_from_the_enrollment_policy():
    payload = {
        "id": "00p1",
        "type": "MFA_ENROLL",
        "status": "ACTIVE",
        "settings": {"factors": {"okta_otp": {"enroll": {"self": "REQUIRED"}}}},
    }
    objects = OktaNormalizer().normalize("mfa_enroll_policy", _raw("mfa_enroll_policy", "00p1", payload))
    assert [(o.attributes["key"], o.attributes["value"]) for o in objects] == [("mfa_enroll_policy_required", True)]


def test_an_enrollment_policy_with_no_factors_emits_nothing():
    """Unknown is not the same as 'not required', so it must not become a row."""
    payload = {"id": "00p2", "type": "MFA_ENROLL", "status": "ACTIVE", "settings": {}}
    assert OktaNormalizer().normalize("mfa_enroll_policy", _raw("mfa_enroll_policy", "00p2", payload)) == []


# -- extended normalizer tests -----------------------------------------------


def test_normalize_behavior_active_sets_effective_true():
    payload = {
        "id": "bhv1",
        "name": "anomalousLocation",
        "type": "ANOMALOUS_LOCATION",
        "status": "ACTIVE",
        "settings": {"evaluateOnSignIn": True},
    }
    objects = OktaNormalizer().normalize("behavior", _raw("behavior", "bhv1", payload))
    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["effective"] is True
    assert value["is_active"] is True
    assert value["evaluate_on_sign_in"] is True


def test_normalize_behavior_inactive_sets_effective_false():
    payload = {
        "id": "bhv2",
        "name": "anomalousDevice",
        "type": "ANOMALOUS_DEVICE",
        "status": "INACTIVE",
        "settings": {"evaluateOnSignIn": False},
    }
    objects = OktaNormalizer().normalize("behavior", _raw("behavior", "bhv2", payload))
    value = objects[0].attributes["value"]
    assert value["effective"] is False
    assert value["is_active"] is False


def test_normalize_log_stream_captures_status():
    payload = {"id": "lgs1", "name": "Splunk", "type": "aws_eventbridge", "status": "ACTIVE"}
    objects = OktaNormalizer().normalize("log_stream", _raw("log_stream", "lgs1", payload))
    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["is_active"] is True
    assert value["name"] == "Splunk"


def test_normalize_auth_server_detects_excessive_token_lifetime():
    payload = {
        "id": "aus1",
        "name": "default",
        "status": "ACTIVE",
        "max_access_token_lifetime_minutes": 480,
    }
    objects = OktaNormalizer().normalize("auth_server", _raw("auth_server", "aus1", payload))
    value = objects[0].attributes["value"]
    assert value["token_lifetime_excessive"] is True


def test_normalize_auth_server_detects_wildcard_scope():
    payload = {
        "id": "aus2",
        "name": "internal",
        "status": "ACTIVE",
        "scopes": [{"id": "s1", "name": "*"}],
    }
    objects = OktaNormalizer().normalize("auth_server", _raw("auth_server", "aus2", payload))
    value = objects[0].attributes["value"]
    assert value["has_wildcard_scope"] is True


def test_normalize_iam_role_emits_role_kind_with_permissions():
    payload = {
        "id": "role1",
        "label": "Help Desk",
        "description": "Read-only",
        "type": "CUSTOM",
        "permissions": [{"type": "okta.users.read"}, {"type": "okta.groups.read"}],
    }
    objects = OktaNormalizer().normalize("iam_role", _raw("iam_role", "role1", payload))
    assert len(objects) == 1
    attrs = objects[0].attributes
    assert attrs["role_type"] == "custom_iam"
    assert "okta.users.read" in attrs["permissions"]
    assert attrs["permission_count"] == 2
    assert attrs["is_privileged"] is True


def test_normalize_device_emits_resource_kind():
    payload = {
        "id": "dev1",
        "status": "ACTIVE",
        "managed": True,
        "profile": {"displayName": "MacBook Pro", "platform": "MACOS", "diskEncryptionType": "ALL_INTERNAL_VOLUMES"},
        "linked_users": [{"user": {"id": "00u1"}}],
    }
    objects = OktaNormalizer().normalize("device", _raw("device", "dev1", payload))
    assert len(objects) == 1
    attrs = objects[0].attributes
    assert attrs["resource_type"] == "device"
    assert attrs["platform"] == "MACOS"
    assert attrs["disk_encrypted"] is True
    assert "00u1" in attrs["linked_user_ids"]


def test_system_log_expanded_event_types_are_mapped():
    """Spot-check a sample of extended System Log mappings."""
    test_cases = [
        ("policy.lifecycle.deactivate", "policy.change"),
        ("zone.update", "config.change"),
        ("user.session.impersonation.initiate", "admin.console"),
        ("iam.role.member.add", "privilege.grant"),
        ("device.lifecycle.activate", "device.enroll"),
        ("system.log_stream.create", "config.change"),
        ("user.lifecycle.reactivate", "dormant.reactivate"),
        ("app.lifecycle.create", "oauth.app.install"),
        ("event_hook.create", "webhook.create"),
    ]
    normalizer = OktaNormalizer()
    for okta_event, expected_action in test_cases:
        payload = {
            "uuid": f"uuid-{okta_event}",
            "eventType": okta_event,
            "published": "2026-08-10T12:00:00Z",
            "actor": {"id": "00u1", "alternateId": "ada@acme.test"},
        }
        objects = normalizer.normalize("system_log", _raw("system_log", f"uuid-{okta_event}", payload))
        assert len(objects) == 1, f"Event '{okta_event}' should map to an action"
        assert objects[0].attributes["action"] == expected_action, f"Event '{okta_event}' should map to '{expected_action}'"


def test_system_log_uses_category_for_to_compute_action_category():
    """action_category must come from category_for(), not a stale local dict."""
    payload = {
        "uuid": "uuid-1",
        "eventType": "device.lifecycle.activate",
        "published": "2026-08-10T12:00:00Z",
        "actor": {"id": "00u1", "alternateId": "ada@acme.test"},
    }
    objects = OktaNormalizer().normalize("system_log", _raw("system_log", "uuid-1", payload))
    assert objects[0].attributes["action_category"] == "device"


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        ({"userType": "Contractor"}, "contractor"),
        ({"userType": "contingent worker"}, "contractor"),
        ({"userType": "Vendor"}, "vendor_or_partner"),
        ({"userType": "Employee"}, "employee"),
        ({"userType": "FTE"}, "employee"),
        ({"isExternal": True}, "contractor"),
        ({"userType": "Employee", "isExternal": True}, "employee"),
        ({}, "unknown"),
        ({"userType": ""}, "unknown"),
    ],
)
def test_user_worker_type_comes_from_user_type_then_is_external(profile, expected):
    raw = _raw("user", "1", {"id": 1, "status": "ACTIVE", "profile": {"login": "x@example.com", **profile}})

    identity = OktaNormalizer().normalize("user", raw)[0]

    assert identity.attributes["worker_type"] == expected
    # The legacy flag keeps its original meaning for the shipped packs.
    assert identity.attributes["is_external"] is bool(profile.get("userType") == "Contractor" or profile.get("isExternal"))


def test_user_profile_fields_are_carried_and_the_manager_is_only_an_email_when_address_shaped():
    raw = _raw(
        "user",
        "1",
        {
            "id": 1,
            "status": "ACTIVE",
            "profile": {
                "login": "x@example.com",
                "department": "Platform",
                "title": "SRE",
                "managerId": "lead@example.com",
                "employeeNumber": "E-42",
                "organization": "Acme",
                "userType": "Employee",
            },
        },
    )

    attrs = OktaNormalizer().normalize("user", raw)[0].attributes

    assert (attrs["department"], attrs["title"], attrs["manager_email"]) == ("Platform", "SRE", "lead@example.com")
    assert attrs["manager_ref"] is None
    assert (attrs["employee_number"], attrs["organization"], attrs["user_type"]) == ("E-42", "Acme", "Employee")

    raw.payload["profile"]["managerId"] = "00u-manager-id"
    attrs = OktaNormalizer().normalize("user", raw)[0].attributes
    assert attrs["manager_email"] is None
    assert attrs["manager_ref"] == "00u-manager-id"


def test_user_disabled_at_is_status_changed_only_while_disabled():
    disabled = _raw(
        "user",
        "1",
        {"id": 1, "status": "DEPROVISIONED", "statusChanged": "2026-05-01T00:00:00Z", "profile": {"login": "x@example.com"}},
    )
    active = _raw(
        "user",
        "2",
        {"id": 2, "status": "ACTIVE", "statusChanged": "2026-05-01T00:00:00Z", "profile": {"login": "y@example.com"}},
    )

    assert OktaNormalizer().normalize("user", disabled)[0].attributes["disabled_at"] == datetime(2026, 5, 1, tzinfo=UTC)
    assert OktaNormalizer().normalize("user", active)[0].attributes["disabled_at"] is None
    assert OktaNormalizer().normalize("user", disabled)[0].attributes["status"] == "DEPROVISIONED"


def test_api_token_is_a_service_account_owned_by_its_user():
    raw = _raw("api_token", "tok1", {"id": "tok1", "name": "CI", "userId": "00uowner", "created": "2026-01-01T00:00:00Z"})

    attrs = OktaNormalizer().normalize("api_token", raw)[0].attributes

    assert attrs["worker_type"] == "service"
    assert attrs["owner_identity_ref"] == "00uowner"
