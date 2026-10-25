# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for OktaCollector's degradation behaviour.

An Okta API token inherits its creating admin's permissions rather than
carrying OAuth scopes, so partial access is the normal case, not an edge case:
a token made by a non-super admin reads the directory fine and 403s on
`/api/v1/api-tokens`, `/api/v1/logs`, and policies.

every one of those returned an empty list with nothing
recorded. The run reported SUCCESS, `detect_deletions` read the absent rows as
removal, and `/changes` filled with revocations that never happened. These
tests pin the two halves of the fix: gated families are recorded, and
throttled ones are not mistaken for gated.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kestrel_connector_okta.client import OktaClient
from kestrel_connector_okta.collector import OktaCollector

ORG_URL = "https://acme.okta.com"


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", f"{ORG_URL}/api/v1/x")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class _CannedTransport:
    """Serves canned bodies by path prefix; raises canned errors."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def _lookup(self, path: str) -> Any:
        for prefix, value in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(prefix):
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        return self._lookup(path)

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        data = self._lookup(path)
        # Same contract as FixtureTransport: a list is a page of rows, an
        # envelope (``{"value": [...]}``) is one page the client unwraps.
        if isinstance(data, list):
            yield from data
        else:
            yield data


_USER = {"id": "00u1", "status": "ACTIVE", "profile": {"login": "ada@acme.test", "email": "ada@acme.test"}}
_GROUP = {"id": "00g1", "profile": {"name": "Engineering"}}
_APP = {"id": "0oa1", "label": "GitHub", "signOnMode": "SAML_2_0", "status": "ACTIVE"}

_BASE: dict[str, Any] = {
    "/api/v1/org": {"id": "org1", "subdomain": "acme"},
    "/api/v1/users/00u1/factors": [{"id": "f1", "status": "ACTIVE"}],
    "/api/v1/users/00u1/roles": [{"type": "SUPER_ADMIN", "id": "r1"}],
    "/api/v1/users": [_USER],
    "/api/v1/groups/00g1/users": [_USER],
    "/api/v1/groups/00g1/roles": [],
    "/api/v1/groups": [_GROUP],
    "/api/v1/apps/0oa1/users": [],
    "/api/v1/apps/0oa1/groups": [],
    "/api/v1/apps": [_APP],
    "/api/v1/logs": [{"uuid": "e1", "eventType": "user.session.start", "published": "2026-01-01T00:00:00Z"}],
    "/api/v1/policies/p1/rules": [
        {
            "id": "r1",
            "name": "Default Rule",
            "status": "ACTIVE",
            "actions": {"signon": {"requireFactor": False, "session": {"maxSessionLifetimeMinutes": 0}}},
        }
    ],
    "/api/v1/policies": [{"id": "p1", "name": "Default", "settings": {}}],
    "/api/v1/authenticators": [{"id": "a1", "key": "okta_verify", "name": "Okta Verify"}],
    "/api/v1/zones": [{"id": "nzo1", "name": "Office", "usage": "POLICY"}],
    "/api/v1/trustedOrigins": [{"id": "tos1", "name": "App", "origin": "https://app.test"}],
    "/api/v1/eventHooks": [{"id": "who1", "name": "SIEM", "channel": {"config": {"uri": "https://siem.test/h"}}}],
    "/api/v1/inlineHooks": [{"id": "cal1", "name": "Import", "channel": {"config": {"uri": "https://auth.test/v"}}}],
    "/api/v1/idps": [{"id": "idp1", "name": "Partner", "type": "SAML2"}],
    "/api/v1/groups/rules": [{"id": "0pr1", "name": "Rule", "status": "ACTIVE"}],
    "/api/v1/device-assurances": [{"id": "d1", "name": "macOS baseline"}],
    "/api/v1/threats/configuration": {"action": "audit"},
    "/api/v1/api-tokens": [{"id": "t1", "name": "ci"}],
    # Orgs without the IAM assignees endpoint: the role walk covers every user.
    "/api/v1/iam/assignees/users": _http_error(404),
    # Extended families (empty by default; tests can override)
    "/api/v1/behaviors": [],
    "/api/v1/logStreams": [],
    "/api/v1/authorizationServers": [],
    "/api/v1/iam/roles": [],
    "/api/v1/iam/resource-sets": [],
    "/api/v1/devices": [],
}


def _collector(overrides: dict[str, Any] | None = None) -> tuple[OktaCollector, _CannedTransport]:
    transport = _CannedTransport({**_BASE, **(overrides or {})})
    return OktaCollector(OktaClient(transport, org_url=ORG_URL)), transport


def _drain(collector: OktaCollector) -> dict[str, int]:
    return {object_type: len(list(collector.collect(object_type))) for object_type in collector.discover()}


def test_a_full_run_collects_every_object_type_and_records_no_skips() -> None:
    collector, _ = _collector()
    counts = _drain(collector)
    assert counts["user"] == 1
    assert counts["group"] == 1
    assert counts["app"] == 1
    assert counts["system_log"] == 1
    assert counts["api_token"] == 1
    assert collector.skipped_object_types == {}


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("system_log", "/api/v1/logs"),
        ("api_token", "/api/v1/api-tokens"),
        ("threat_insight", "/api/v1/threats/configuration"),
        ("password_policy", "/api/v1/policies"),
    ],
)
def test_a_permission_gated_optional_family_is_recorded_not_swallowed(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _http_error(403)})
    assert list(collector.collect(object_type)) == []
    assert collector.skipped_object_types == {object_type: "permission"}


def test_a_gated_family_does_not_stop_the_rest_of_the_tenant_collecting() -> None:
    collector, _ = _collector({"/api/v1/api-tokens": _http_error(403)})
    counts = _drain(collector)
    assert counts["api_token"] == 0
    assert counts["user"] == 1
    assert counts["group"] == 1
    assert collector.skipped_object_types == {"api_token": "permission"}


def test_a_throttled_family_raises_rather_than_reporting_zero_rows() -> None:
    # This is the bug: `_safe_list` treated an exhausted 429 as a permission
    # gate, so a throttled sync looked exactly like a tenant with no API tokens.
    collector, _ = _collector({"/api/v1/api-tokens": _http_error(429)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("api_token"))
    assert collector.skipped_object_types == {}


def test_a_throttled_nested_call_also_raises() -> None:
    collector, _ = _collector({"/api/v1/users/00u1/roles": _http_error(429)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("role_assignment"))
    assert collector.skipped_object_types == {}


def test_a_failure_on_a_required_object_type_still_fails_the_run() -> None:
    # Directory reads are core. A 403 here means the token cannot see the org,
    # which the health check's permission message is the right way to surface.
    collector, _ = _collector({"/api/v1/users": _http_error(403)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("user"))
    assert collector.skipped_object_types == {}


def test_a_gated_nested_call_records_its_sub_family_once() -> None:
    # A token that cannot read one user's roles cannot read any of them, so the
    # skip is recorded per sub-family, not per entity.
    collector, _ = _collector({"/api/v1/users/00u1/roles": _http_error(403)})
    assert list(collector.collect("role_assignment")) == []
    assert collector.skipped_object_types == {"role_assignment.user_roles": "permission"}


def test_unreadable_factors_degrade_mfa_state_without_failing_the_user_sync() -> None:
    collector, _ = _collector({"/api/v1/users/00u1/factors": _http_error(403)})
    users = list(collector.collect("user"))
    assert len(users) == 1
    # No factors readable -> no active factor found. The skip is what tells the
    # operator the answer is unknown rather than negative.
    assert collector.skipped_object_types == {"user.factors": "permission"}


def test_an_unknown_object_type_is_rejected() -> None:
    collector, _ = _collector()
    with pytest.raises(ValueError, match="does not support object_type"):
        list(collector.collect("nope"))


# -- authentication and session policy surface ---------------------


@pytest.mark.parametrize(
    "object_type",
    ["access_policy", "sign_on_policy", "profile_enrollment_policy", "idp_discovery_policy"],
)
def test_each_policy_type_is_collected_with_its_rules(object_type: str) -> None:
    collector, _ = _collector()

    rows = list(collector.collect(object_type))

    assert len(rows) == 1
    assert rows[0].payload["rules"][0]["id"] == "r1"


def test_unreadable_policy_rules_are_recorded_rather_than_read_as_no_rules() -> None:
    """The dangerous failure mode for this family.

    A policy with no rules and a policy whose rules could not be read look
    identical in the payload -- and "no rules" summarizes as a policy that
    requires nothing and expires nothing. Recording the skip is what keeps a
    permission gap from being reported as a wide-open sign-on policy.
    """
    collector, _ = _collector({"/api/v1/policies/p1/rules": _http_error(403)})

    rows = list(collector.collect("sign_on_policy"))

    assert rows[0].payload["rules"] == []
    assert collector.skipped_object_types == {"sign_on_policy.rules": "permission"}


def test_a_throttled_rules_read_still_fails_the_run() -> None:
    collector, _ = _collector({"/api/v1/policies/p1/rules": _http_error(429)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("sign_on_policy"))


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("authenticator", "/api/v1/authenticators"),
        ("device_assurance_policy", "/api/v1/device-assurances"),
        ("access_policy", "/api/v1/policies"),
    ],
)
def test_the_new_families_degrade_rather_than_failing(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _http_error(403)})

    assert list(collector.collect(object_type)) == []
    assert object_type in collector.skipped_object_types


def test_a_policy_without_an_id_is_skipped_rather_than_fetched() -> None:
    collector, _ = _collector({"/api/v1/policies": [{"name": "nameless"}]})
    assert list(collector.collect("access_policy")) == []


# -- perimeter and automation surface ------------------------------


def test_a_hook_callout_url_and_auth_header_never_reach_a_raw_object() -> None:
    """An inline hook's endpoint changes the outcome of a sign-in.

    Its URL carries authentication and is itself a trust boundary, so neither
    it nor the auth header may reach `raw_source`, which is persisted verbatim.
    """
    collector, _ = _collector(
        {
            "/api/v1/eventHooks": [
                {
                    "id": "who1",
                    "name": "SIEM",
                    "channel": {
                        "config": {
                            "uri": "https://siem.example.test/okta?token=tok-en",
                            "authScheme": {"type": "HEADER", "value": "header-secret"},
                            "headers": [{"key": "X-Api-Key", "value": "another-secret"}],
                        }
                    },
                }
            ]
        }
    )

    hooks = list(collector.collect("event_hook"))

    payload = str(hooks[0].payload)
    assert "tok-en" not in payload
    assert "header-secret" not in payload
    assert "another-secret" not in payload
    config = hooks[0].payload["channel"]["config"]
    assert config["uri_host"] == "siem.example.test"
    assert "uri" not in config


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("network_zone", "/api/v1/zones"),
        ("trusted_origin", "/api/v1/trustedOrigins"),
        ("event_hook", "/api/v1/eventHooks"),
        ("inline_hook", "/api/v1/inlineHooks"),
        ("identity_provider", "/api/v1/idps"),
        ("group_rule", "/api/v1/groups/rules"),
    ],
)
def test_each_perimeter_family_degrades_rather_than_failing(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _http_error(403)})

    assert list(collector.collect(object_type)) == []
    assert collector.skipped_object_types == {object_type: "permission"}


def test_a_row_without_an_id_is_skipped_rather_than_stored_under_an_empty_key() -> None:
    collector, _ = _collector({"/api/v1/zones": [{"name": "nameless"}]})
    assert list(collector.collect("network_zone")) == []


def test_role_walk_only_asks_users_that_hold_a_role() -> None:
    transport = _CannedTransport(
        {
            **_BASE,
            "/api/v1/users": [_USER, {"id": "00u2", "status": "ACTIVE", "profile": {"login": "b@acme.test"}}],
            "/api/v1/iam/assignees/users": {"value": [{"id": "00u1", "orn": "orn:okta:directory:org1:users:00u1"}]},
            "/api/v1/users/00u2/factors": [],
        }
    )
    collector = OktaCollector(OktaClient(transport, org_url=ORG_URL))
    assignments = list(collector.collect("role_assignment"))
    assert [a.payload["user_id"] for a in assignments if a.payload["assignment_type"] == "USER"] == ["00u1"]
    assert any("/api/v1/users/00u1/roles" in c for c in transport.calls)
    assert not any("/api/v1/users/00u2/roles" in c for c in transport.calls)
    assert collector.skipped_object_types == {}


def test_role_walk_falls_back_to_every_user_when_assignees_is_unavailable() -> None:
    transport = _CannedTransport(
        {
            **_BASE,
            "/api/v1/users": [_USER, {"id": "00u2", "status": "ACTIVE", "profile": {"login": "b@acme.test"}}],
            "/api/v1/iam/assignees/users": _http_error(404),
            "/api/v1/users/00u2/factors": [],
            "/api/v1/users/00u2/roles": [],
        }
    )
    collector = OktaCollector(OktaClient(transport, org_url=ORG_URL))
    list(collector.collect("role_assignment"))
    assert any("/api/v1/users/00u2/roles" in c for c in transport.calls)


def test_factor_fan_out_still_labels_every_user() -> None:
    transport = _CannedTransport(
        {
            **_BASE,
            "/api/v1/users": [_USER, {"id": "00u2", "status": "ACTIVE", "profile": {"login": "b@acme.test"}}],
            "/api/v1/users/00u2/factors": [],
        }
    )
    collector = OktaCollector(OktaClient(transport, org_url=ORG_URL))
    by_id = {u.provider_id: u.payload for u in collector.collect("user")}
    assert by_id["00u1"]["mfa_enabled"] is True
    assert by_id["00u2"]["mfa_enabled"] is False


def test_service_app_scopes_come_from_granted_scopes_not_the_requested_list() -> None:
    service = {
        "id": "0oa9",
        "label": "CI",
        "signOnMode": "OPENID_CONNECT",
        "status": "ACTIVE",
        "settings": {
            "oauthClient": {
                "application_type": "service",
                "grant_types": ["client_credentials"],
                "scopes": ["okta.users.read"],
            }
        },
    }
    collector, transport = _collector(
        {
            "/api/v1/apps": [_APP, service],
            "/api/v1/apps/0oa9/users": [],
            "/api/v1/apps/0oa9/groups": [],
            "/api/v1/apps/0oa9/grants": [
                {"scopeId": "okta.users.manage", "status": "ACTIVE"},
                {"scopeId": "okta.apps.manage", "status": "REVOKED"},
            ],
        }
    )
    scopes = {s.provider_id for s in collector.collect("app_scope")}
    assert "0oa9:okta.users.manage" in scopes
    assert "0oa9:okta.apps.manage" not in scopes
    assert "0oa9:okta.users.read" not in scopes
    # The web app never hits /grants.
    assert not any("/apps/0oa1/grants" in c for c in transport.calls)


# -- Extended: new families -----------------------------------------------


def test_release_b_families_are_in_discover() -> None:
    collector, _ = _collector()
    types = collector.discover()
    for family in ("behavior", "log_stream", "auth_server", "iam_role", "resource_set", "device"):
        assert family in types, f"'{family}' missing from discover()"


def test_behaviors_are_collected() -> None:
    collector, _ = _collector(
        {
            "/api/v1/behaviors": [
                {"id": "bhv1", "name": "anomalousLocation", "type": "ANOMALOUS_LOCATION", "status": "ACTIVE"},
                {"id": "bhv2", "name": "anomalousDevice", "type": "ANOMALOUS_DEVICE", "status": "INACTIVE"},
            ]
        }
    )
    rows = list(collector.collect("behavior"))
    assert len(rows) == 2
    assert rows[0].provider_id == "bhv1"


def test_log_streams_are_collected() -> None:
    collector, _ = _collector(
        {"/api/v1/logStreams": [{"id": "lgs1", "name": "Splunk", "type": "aws_eventbridge", "status": "ACTIVE"}]}
    )
    rows = list(collector.collect("log_stream"))
    assert len(rows) == 1
    assert rows[0].provider_id == "lgs1"


def test_auth_servers_are_collected_with_policies_and_scopes_attached() -> None:
    collector, _ = _collector(
        {
            "/api/v1/authorizationServers": [{"id": "aus1", "name": "default", "status": "ACTIVE"}],
            "/api/v1/authorizationServers/aus1/policies": [{"id": "pol1", "accessTokenLifetimeMinutes": 120}],
            "/api/v1/authorizationServers/aus1/scopes": [{"id": "scp1", "name": "openid"}],
        }
    )
    rows = list(collector.collect("auth_server"))
    assert len(rows) == 1
    assert rows[0].provider_id == "aus1"
    payload = rows[0].payload
    assert len(payload["policies"]) == 1
    assert len(payload["scopes"]) == 1
    assert payload["max_access_token_lifetime_minutes"] == 120


def test_iam_roles_are_collected_with_permissions_attached() -> None:
    collector, _ = _collector(
        {
            "/api/v1/iam/roles": [{"id": "role1", "label": "Help Desk", "type": "CUSTOM"}],
            "/api/v1/iam/roles/role1/permissions": [{"type": "okta.users.read"}],
        }
    )
    rows = list(collector.collect("iam_role"))
    assert len(rows) == 1
    assert rows[0].payload["permissions"][0]["type"] == "okta.users.read"


def test_devices_are_collected_with_linked_users() -> None:
    collector, _ = _collector(
        {
            "/api/v1/devices": [{"id": "dev1", "status": "ACTIVE", "profile": {"platform": "MACOS"}}],
            "/api/v1/devices/dev1/users": [{"user": {"id": "00u1"}}],
        }
    )
    rows = list(collector.collect("device"))
    assert len(rows) == 1
    assert rows[0].payload["linked_users"][0]["user"]["id"] == "00u1"


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("behavior", "/api/v1/behaviors"),
        ("log_stream", "/api/v1/logStreams"),
        ("auth_server", "/api/v1/authorizationServers"),
        ("iam_role", "/api/v1/iam/roles"),
        ("resource_set", "/api/v1/iam/resource-sets"),
        ("device", "/api/v1/devices"),
    ],
)
def test_release_b_family_degrades_on_403(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _http_error(403)})
    assert list(collector.collect(object_type)) == []
    assert object_type in collector.skipped_object_types


def test_gated_service_app_grants_fall_back_to_the_requested_scopes() -> None:
    service = {
        "id": "0oa9",
        "label": "CI",
        "signOnMode": "OPENID_CONNECT",
        "status": "ACTIVE",
        "settings": {
            "oauthClient": {
                "application_type": "service",
                "grant_types": ["client_credentials"],
                "scopes": ["okta.users.read"],
            }
        },
    }
    collector, _ = _collector(
        {
            "/api/v1/apps": [_APP, service],
            "/api/v1/apps/0oa9/users": [],
            "/api/v1/apps/0oa9/groups": [],
            "/api/v1/apps/0oa9/grants": _http_error(403),
        }
    )
    scopes = {s.provider_id for s in collector.collect("app_scope")}
    assert "0oa9:okta.users.read" in scopes
    assert collector.skipped_object_types == {"app_scope.grants": "permission"}
