# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`SlackNormalizer`: pure `RawObject -> NormalizedObject` mapping, built from
hand-written payloads only (see the fixture-contract rule in
`test_connector_fixture_contract.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.connectors.sdk.base import RawObject
from kestrel_connector_slack.normalizer import (
    SlackNormalizer,
    _anomaly_allowlist_configured,
    _installer_user_id,
    _is_sensitive_scope,
    _kestrel_action_for_slack_audit,
    _parse_slack_ts,
)

_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _raw(object_type: str, provider_id: str, payload: dict) -> RawObject:
    return RawObject(object_type=object_type, provider_id=provider_id, payload=payload, collected_at=_NOW)


def test_normalize_raises_for_an_unknown_object_type():
    with pytest.raises(ValueError, match="widget"):
        SlackNormalizer().normalize("widget", _raw("widget", "1", {}))


def test_parse_slack_ts_handles_none_and_empty_string():
    assert _parse_slack_ts(None) is None
    assert _parse_slack_ts("") is None


def test_parse_slack_ts_from_unix_seconds_float():
    assert _parse_slack_ts(1_772_323_200.123456) == datetime.fromtimestamp(1_772_323_200.123456, tz=UTC)


def test_parse_slack_ts_from_unix_milliseconds_is_detected_and_scaled():
    seconds_value = 1_772_323_200
    ms_value = seconds_value * 1000
    assert _parse_slack_ts(ms_value) == datetime.fromtimestamp(seconds_value, tz=UTC)


def test_parse_slack_ts_from_digit_string_is_treated_as_unix_seconds():
    assert _parse_slack_ts("1772323200") == datetime.fromtimestamp(1772323200, tz=UTC)


def test_parse_slack_ts_from_iso_string_with_z_suffix():
    assert _parse_slack_ts("2026-07-01T12:00:00Z") == datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


def test_parse_slack_ts_from_unparseable_string_returns_none():
    assert _parse_slack_ts("not-a-timestamp") is None


def test_parse_slack_ts_passes_through_a_datetime():
    naive = datetime(2026, 7, 1, 12, 0)
    assert _parse_slack_ts(naive) == naive.replace(tzinfo=UTC)


def test_is_sensitive_scope_matches_curated_set_and_admin_prefix():
    assert _is_sensitive_scope("chat:write") is True
    assert _is_sensitive_scope("admin.conversations:write") is True
    assert _is_sensitive_scope("channels:write.invites") is False


def test_installer_user_id_prefers_explicit_field_then_last_resolved_by():
    assert _installer_user_id({"installer_user_id": "u1"}) == "u1"
    assert _installer_user_id({"last_resolved_by": {"actor_id": "u2"}}) == "u2"
    assert _installer_user_id({}) is None


def test_anomaly_allowlist_configured_true_when_cidrs_or_asns_present():
    assert _anomaly_allowlist_configured({"trusted_cidrs": ["10.0.0.0/8"]}) is True
    assert _anomaly_allowlist_configured({"trustedAsns": [64500]}) is True


def test_anomaly_allowlist_configured_false_when_keys_present_but_empty():
    assert _anomaly_allowlist_configured({"trusted_cidrs": [], "trusted_asns": []}) is False


def test_anomaly_allowlist_configured_false_when_keys_absent():
    assert _anomaly_allowlist_configured({}) is False


def test_kestrel_action_for_slack_audit_maps_known_actions_and_drops_others():
    assert _kestrel_action_for_slack_audit({"action": "role_change_to_admin"}) == "privilege.grant"
    assert _kestrel_action_for_slack_audit({"action": "some_unmapped_action"}) is None


def test_user_is_bot_detected_by_flag_or_slackbot_id():
    normalizer = SlackNormalizer()
    bot = _raw("user", "U1", {"id": "U1", "is_bot": True, "profile": {}})
    slackbot = _raw("user", "USLACKBOT", {"id": "USLACKBOT", "profile": {}})
    human = _raw("user", "U2", {"id": "U2", "is_bot": False, "profile": {"real_name": "A Human"}})

    assert normalizer.normalize("user", bot)[0].attributes["identity_type"] == "service_account"
    assert normalizer.normalize("user", slackbot)[0].attributes["identity_type"] == "service_account"
    assert normalizer.normalize("user", human)[0].attributes["identity_type"] == "user"


def test_user_is_external_when_restricted_or_ultra_restricted():
    normalizer = SlackNormalizer()
    guest = _raw("user", "U1", {"id": "U1", "is_restricted": True, "profile": {}})
    multi_guest = _raw("user", "U2", {"id": "U2", "is_ultra_restricted": True, "profile": {}})
    full_member = _raw("user", "U3", {"id": "U3", "profile": {}})

    assert normalizer.normalize("user", guest)[0].attributes["is_external"] is True
    assert normalizer.normalize("user", multi_guest)[0].attributes["is_external"] is True
    assert normalizer.normalize("user", full_member)[0].attributes["is_external"] is False


def test_oauth_scope_honors_an_explicit_is_sensitive_override():
    raw = _raw(
        "oauth_scope",
        "1",
        {"app_id": "app-1", "scope_name": "not-normally-sensitive", "is_sensitive": True},
    )

    scope = SlackNormalizer().normalize("oauth_scope", raw)[0]

    assert scope.attributes["is_sensitive"] is True


def test_oauth_scope_falls_back_to_the_curated_sensitivity_set():
    raw = _raw("oauth_scope", "1", {"app_id": "app-1", "scope_name": "chat:write"})

    scope = SlackNormalizer().normalize("oauth_scope", raw)[0]

    assert scope.attributes["is_sensitive"] is True


def test_shared_channel_external_emits_a_sharing_setting_row():
    raw = _raw("shared_channel", "C1", {"name": "ext-channel", "is_ext_shared": True})

    objects = SlackNormalizer().normalize("shared_channel", raw)

    kinds = [o.kind for o in objects]
    assert kinds == ["resource", "setting"]
    assert objects[0].attributes["is_external"] is True
    assert objects[1].attributes["key"] == "external_shared_channel"


def test_shared_channel_that_is_not_shared_is_a_plain_channel():
    raw = _raw("shared_channel", "C2", {"name": "general", "is_ext_shared": False, "is_shared": False, "is_private": True})

    objects = SlackNormalizer().normalize("shared_channel", raw)

    assert [o.kind for o in objects] == ["resource"]
    assert objects[0].attributes["is_external"] is False
    assert objects[0].attributes["visibility"] == "private"


def test_user_last_active_prefers_an_audit_login_over_the_profile_timestamp():
    raw = _raw("user", "U1", {"profile": {"email": "a@x.test"}, "updated": 1735689600, "last_login_at": 1736000000})

    identity = SlackNormalizer().normalize("user", raw)[0]

    assert identity.attributes["last_active_at"] == datetime.fromtimestamp(1736000000, tz=UTC)
    assert identity.attributes["last_active_source"] == "audit"


def test_user_last_active_from_profile_is_labeled_as_such():
    raw = _raw("user", "U1", {"profile": {"email": "a@x.test"}, "updated": 1735689600})

    identity = SlackNormalizer().normalize("user", raw)[0]

    assert identity.attributes["last_active_source"] == "profile"


def test_user_without_any_timestamp_has_no_activity_source():
    identity = SlackNormalizer().normalize("user", _raw("user", "U1", {"profile": {"email": "a@x.test"}}))[0]

    assert "last_active_at" not in identity.attributes
    assert "last_active_source" not in identity.attributes


def test_audit_log_event_with_no_mapped_action_emits_nothing():
    raw = _raw("audit_log", "evt-1", {"action": "some_unmapped_action"})

    assert SlackNormalizer().normalize("audit_log", raw) == []


def test_audit_log_event_with_a_mapped_action_carries_actor_and_entity():
    raw = _raw(
        "audit_log",
        "evt-2",
        {
            "action": "role_change_to_admin",
            "date_create": 1772323200,
            "actor": {"user": {"id": "actor-1", "email": "actor@example.com"}},
            "entity": {"user": {"id": "entity-1", "email": "entity@example.com"}},
        },
    )

    event = SlackNormalizer().normalize("audit_log", raw)[0]

    assert event.attributes["action"] == "privilege.grant"
    assert event.attributes["actor_provider_id"] == "actor-1"
    assert event.attributes["target_provider_id"] == "entity-1"
    assert event.attributes["target_type"] == "identity"


def test_guest_tier_is_labeled_on_the_identity():
    normalizer = SlackNormalizer()
    multi = normalizer.normalize("user", _raw("user", "U1", {"is_restricted": True, "profile": {}}))[0].attributes
    single = normalizer.normalize("user", _raw("user", "U2", {"is_ultra_restricted": True, "profile": {}}))[0].attributes
    member = normalizer.normalize("user", _raw("user", "U3", {"is_admin": True, "profile": {}}))[0].attributes
    assert (multi["guest_type"], multi["is_external"]) == ("multi_channel_guest", True)
    assert (single["guest_type"], single["is_external"]) == ("single_channel_guest", True)
    assert (member["guest_type"], member["is_external"], member["is_admin"]) == (None, False, True)


def test_channel_with_membership_emits_a_grant_per_member():
    raw = _raw("channel", "C2", {"name": "secret", "is_private": True, "num_members": 2, "member_ids": ["U1", "U2"]})

    objects = SlackNormalizer().normalize("channel", raw)

    assert [o.kind for o in objects] == ["resource", "grant", "grant"]
    channel = objects[0].attributes
    assert channel["visibility"] == "private"
    assert channel["config"]["is_private"] is True
    assert channel["config"]["is_external"] is False
    grant = objects[1]
    assert grant.attributes == {
        "identity_ref": "U1",
        "resource_ref": "C2",
        "granted_via": "direct",
        "permission_level": "member",
    }
    assert grant.relationships[0].edge_type == "can_access"


def test_public_channel_without_membership_is_just_a_resource():
    raw = _raw("channel", "C1", {"name": "general", "is_private": False, "num_members": 40})
    objects = SlackNormalizer().normalize("channel", raw)
    assert [o.kind for o in objects] == ["resource"]
    assert objects[0].attributes["visibility"] == "public"


# Slack's documented responses. Neither `team.info` nor
# `admin.teams.settings.info` exposes 2FA enforcement, app approval, SSO, or
# session duration -- those were emitted from fixture-only fields. The workspace
# guard made it worse than a silent miss: it fired whenever *any* value was
# present, and `domain` always is, so a live workspace produced a full set of
# settings whose values were null. `slack-sso-not-enforced` reads
# `bool(value_bool)`, so a null opened a high-severity finding on every tenant.
_TEAM_INFO_FIELDS = {
    "id": "T1",
    "name": "Acme",
    "domain": "acme",
    "email_domain": "acme.example.com",
    "icon": {"image_default": True},
    "enterprise_id": "E1",
    "enterprise_name": "Acme Grid",
}
_FABRICATED = ("two_factor_required", "app_approval_enabled", "sso_enabled")


def test_team_info_emits_only_settings_slack_actually_returns():
    raw = _raw("team", "T1", dict(_TEAM_INFO_FIELDS))
    keys = {o.attributes["key"] for o in SlackNormalizer().normalize("team", raw) if o.kind == "setting"}
    assert keys == {"domain"}


def test_workspace_settings_does_not_invent_null_rows():
    """The regression: `domain` alone must not drag in four null settings."""
    payload = {**_TEAM_INFO_FIELDS, "default_channels": []}
    objects = SlackNormalizer().normalize("workspace", _raw("workspace", "T1", payload))
    settings = {o.attributes["key"]: o.attributes["value"] for o in objects if o.kind == "setting"}
    assert settings == {"domain": "acme"}
    for key in _FABRICATED:
        assert key not in settings


def test_workspace_emits_a_setting_only_when_the_payload_carries_a_value():
    payload = {**_TEAM_INFO_FIELDS, "session_duration_hours": 24}
    objects = SlackNormalizer().normalize("workspace", _raw("workspace", "T1", payload))
    settings = {o.attributes["key"] for o in objects if o.kind == "setting"}
    # session_duration_hours is no longer a team-level spec, so it is ignored
    # here even when present; the real source is the per-user session settings.
    assert settings == {"domain"}


def test_session_duration_is_scoped_to_the_account_it_governs():
    raw = _raw("user_session_setting", "U1", {"user_id": "U1", "duration": 43200, "desktop_app_browser_quit": True})
    objects = SlackNormalizer().normalize("user_session_setting", raw)
    assert len(objects) == 1
    setting = objects[0]
    assert setting.attributes["key"] == "session_duration_hours"
    assert setting.attributes["value"] == 12.0  # seconds -> hours
    assert setting.attributes["subject_type"] == "identity"
    assert setting.attributes["subject_ref"] == "U1"
    assert [(r.edge_type, r.target_ref) for r in setting.relationships] == [("applies_to", "U1")]


def test_an_account_with_no_session_setting_gets_no_row():
    """Absent from the response means Slack applied no explicit setting --
    which is not the same as a known duration, so it must not become a row."""
    raw = _raw("user_session_setting", "U2", {"user_id": "U2"})
    assert SlackNormalizer().normalize("user_session_setting", raw) == []
