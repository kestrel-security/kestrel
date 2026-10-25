# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`GitHubNormalizer`: pure `RawObject -> NormalizedObject` mapping, exercised
here with hand-built payloads (never a shipped `connectors/github/fixtures/`
file -- that fixture set gets exactly one contract test, in
`test_connector_fixture_contract.py`, per docs/testing.md
rule 2).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.connectors.sdk.base import RawObject
from kestrel_connector_github.normalizer import GitHubNormalizer

_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _raw(object_type: str, provider_id: str, payload: dict) -> RawObject:
    return RawObject(object_type=object_type, provider_id=provider_id, payload=payload, collected_at=_NOW)


def test_normalize_raises_for_an_unknown_object_type():
    with pytest.raises(ValueError, match="widget"):
        GitHubNormalizer().normalize("widget", _raw("widget", "1", {}))


def test_member_without_admin_role_emits_only_the_identity():
    raw = _raw(
        "member",
        "1001",
        {"id": 1001, "login": "someone", "name": None, "email": None, "org_role": "member", "two_factor_disabled": False},
    )

    objects = GitHubNormalizer().normalize("member", raw)

    assert [o.kind for o in objects] == ["identity"]
    identity = objects[0]
    assert identity.attributes["mfa_enabled"] is True
    assert identity.attributes["is_external"] is False
    assert identity.relationships == []


def test_admin_member_emits_identity_role_and_grant_with_the_assigned_role_edge():
    raw = _raw(
        "member",
        "1002",
        {"id": 1002, "login": "org-admin", "name": None, "email": None, "org_role": "admin", "two_factor_disabled": True},
    )

    objects = GitHubNormalizer().normalize("member", raw)

    assert [o.kind for o in objects] == ["identity", "role", "grant"]
    identity, role, grant = objects
    assert identity.attributes["mfa_enabled"] is False
    assert role.attributes == {"name": "organization_admin", "is_privileged": True}
    assert grant.attributes["identity_ref"] == "1002"
    assert grant.attributes["role_ref"] == "organization_admin"
    assert identity.relationships[0].edge_type == "assigned_role"
    assert identity.relationships[0].source_ref == "1002"
    assert identity.relationships[0].target_ref == "organization_admin"


def test_member_display_name_prefers_profile_name_over_login():
    with_name = _raw(
        "member",
        "1",
        {
            "id": 1,
            "login": "loginname",
            "name": "Real Name",
            "email": None,
            "org_role": "member",
            "two_factor_disabled": False,
        },
    )
    without_name = _raw(
        "member",
        "2",
        {
            "id": 2,
            "login": "loginname2",
            "name": None,
            "email": None,
            "org_role": "member",
            "two_factor_disabled": False,
        },
    )

    normalizer = GitHubNormalizer()
    assert normalizer.normalize("member", with_name)[0].attributes["display_name"] == "Real Name"
    assert normalizer.normalize("member", without_name)[0].attributes["display_name"] == "loginname2"


def test_member_blank_email_is_normalized_to_none():
    raw = _raw(
        "member",
        "1",
        {"id": 1, "login": "x", "name": None, "email": "   ", "org_role": "member", "two_factor_disabled": False},
    )

    identity = GitHubNormalizer().normalize("member", raw)[0]

    assert identity.attributes["email"] is None


def test_member_email_prefers_the_saml_identity_over_the_profile_email():
    raw = _raw(
        "member",
        "1",
        {"id": 1, "login": "x", "email": "personal@example.test", "saml_name_id": "x@acme.test", "org_role": "member"},
    )

    identity = GitHubNormalizer().normalize("member", raw)[0]

    assert identity.attributes["email"] == "x@acme.test"


def test_member_email_skips_an_opaque_saml_name_id_and_uses_scim_username():
    raw = _raw(
        "member",
        "1",
        {"id": 1, "login": "x", "saml_name_id": "urn:opaque:42", "scim_username": "x@acme.test", "org_role": "member"},
    )

    identity = GitHubNormalizer().normalize("member", raw)[0]

    assert identity.attributes["email"] == "x@acme.test"


def test_member_without_any_address_shaped_identity_has_no_email():
    raw = _raw("member", "1", {"id": 1, "login": "x", "saml_name_id": "urn:opaque:42", "org_role": "member"})

    identity = GitHubNormalizer().normalize("member", raw)[0]

    assert identity.attributes["email"] is None


def test_repo_collaborator_permission_level_prefers_admin_then_push_then_read():
    normalizer = GitHubNormalizer()

    admin_raw = _raw(
        "repo_collaborator",
        "1",
        {
            "repo": {"id": 10, "name": "repo-a"},
            "collaborator": {"id": 20, "permissions": {"admin": True, "push": True}},
        },
    )
    write_raw = _raw(
        "repo_collaborator",
        "2",
        {
            "repo": {"id": 10, "name": "repo-a"},
            "collaborator": {"id": 21, "permissions": {"admin": False, "push": True}},
        },
    )
    read_raw = _raw(
        "repo_collaborator",
        "3",
        {
            "repo": {"id": 10, "name": "repo-a"},
            "collaborator": {"id": 22, "permissions": {"admin": False, "push": False}},
        },
    )

    assert normalizer.normalize("repo_collaborator", admin_raw)[0].attributes["permission_level"] == "admin"
    assert normalizer.normalize("repo_collaborator", write_raw)[0].attributes["permission_level"] == "write"
    assert normalizer.normalize("repo_collaborator", read_raw)[0].attributes["permission_level"] == "read"


def test_repo_collaborator_emits_a_direct_can_access_relationship():
    raw = _raw(
        "repo_collaborator",
        "1",
        {"repo": {"id": 10, "name": "repo-a"}, "collaborator": {"id": 20, "permissions": {"admin": True}}},
    )

    grant = GitHubNormalizer().normalize("repo_collaborator", raw)[0]

    assert grant.attributes["granted_via"] == "direct"
    assert grant.relationships[0].access_path == "direct"
    assert grant.relationships[0].source_ref == "20"
    assert grant.relationships[0].target_ref == "10"


@pytest.mark.parametrize(
    ("repo", "expected"),
    [
        ({"visibility": "internal", "private": True}, "internal"),
        ({"visibility": "public", "private": False}, "public"),
        ({"private": True}, "private"),
        ({"private": False}, "public"),
    ],
)
def test_repository_visibility_mapping(repo, expected):
    payload = {"name": "some-repo", **repo}
    raw = _raw("repository", "10", payload)

    resource = GitHubNormalizer().normalize("repository", raw)[0]

    assert resource.attributes["visibility"] == expected


def test_outside_collaborator_is_normalized_as_an_external_identity():
    raw = _raw("outside_collaborator", "99", {"id": 99, "login": "contractor-account"})

    identity = GitHubNormalizer().normalize("outside_collaborator", raw)[0]

    assert identity.attributes["identity_type"] == "external_identity"
    assert identity.attributes["is_external"] is True
    assert identity.attributes["email"] is None


def test_audit_log_entry_with_no_inferable_action_emits_nothing():
    raw = _raw("audit_log", "evt-1", {"action": "org.some_unmapped_event", "data": {}})

    objects = GitHubNormalizer().normalize("audit_log", raw)

    assert objects == []


def test_audit_log_disable_two_factor_requirement_maps_to_mfa_disable():
    raw = _raw(
        "audit_log",
        "evt-2",
        {
            "action": "org.disable_two_factor_requirement",
            "actor": "an-admin",
            "actor_id": 1,
            "created_at": "2026-07-01T00:00:00Z",
            "data": {},
        },
    )

    event = GitHubNormalizer().normalize("audit_log", raw)[0]

    assert event.attributes["action"] == "mfa.disable"
    assert event.attributes["action_category"] == "mfa"
    assert event.attributes["actor_provider_id"] == "1"


def test_the_identity_type_heuristic_github_never_sends_is_gone():
    """`data.identity_type` is not a field GitHub's audit log has.

    The service-account branch that read it, and the `target_type` it set,
    existed only because a fixture invented the field -- so on a live tenant
    neither could ever fire. `repo.add_member` is now read from the curated
    action map instead.
    """
    raw = _raw(
        "audit_log",
        "evt-3",
        {
            "action": "repo.add_member",
            "data": {"identity_type": "service_account", "permission": "admin"},
        },
    )

    event = GitHubNormalizer().normalize("audit_log", raw)[0]

    assert event.attributes["action"] == "access.grant"
    assert event.attributes["target_type"] == "identity"


def test_organization_payload_emits_tenant_setting_rows_for_present_keys_only():
    raw = _raw(
        "organization",
        "1",
        {"two_factor_requirement_enabled": True, "default_repository_permission": "read"},
    )

    settings = GitHubNormalizer().normalize("organization", raw)

    assert {s.attributes["key"] for s in settings} == {
        "two_factor_requirement_enabled",
        "default_repository_permission",
    }
    assert all(s.kind == "setting" for s in settings)


def test_unknown_two_factor_state_normalizes_to_unknown_not_disabled() -> None:
    # The collector sets `two_factor_disabled` to None when it could not read
    # the org's 2FA filter. Coercing that to False here would open an
    # "admin without MFA" finding on every administrator.
    raw = RawObject(
        object_type="member",
        provider_id="1001",
        payload={"id": 1001, "login": "alice", "org_role": "admin", "two_factor_disabled": None},
        collected_at=_NOW,
    )
    identity = GitHubNormalizer().normalize("member", raw)[0]
    assert identity.attributes["mfa_enabled"] is None


def test_a_member_is_not_claimed_active_without_evidence() -> None:
    # GitHub Cloud exposes no per-member disabled state; GHES sends
    # `suspended_at`. Honor it where present rather than asserting everyone
    # is enabled.
    payload = {"id": 1001, "login": "alice", "org_role": "member", "two_factor_disabled": False}
    normalizer = GitHubNormalizer()

    active = normalizer.normalize(
        "member",
        RawObject(object_type="member", provider_id="1001", payload=payload, collected_at=_NOW),
    )[0]
    assert active.attributes["is_disabled"] is False

    suspended = normalizer.normalize(
        "member",
        RawObject(
            object_type="member",
            provider_id="1001",
            payload={**payload, "suspended_at": "2026-01-05T00:00:00Z"},
            collected_at=_NOW,
        ),
    )[0]
    assert suspended.attributes["is_disabled"] is True


def test_audit_events_do_not_invent_noreply_email_addresses() -> None:
    # @users.noreply.github.com addresses are not real mailboxes and match no
    # identity in any other connector. Correlation runs on provider ids.
    raw = RawObject(
        object_type="audit_log",
        provider_id="audit-1",
        payload={
            "action": "org.disable_member_two_factor",
            "actor": "alice",
            "actor_id": 1001,
            "user": "erin",
            "user_id": 1005,
            "created_at": "2026-07-27T10:00:00Z",
            "data": {},
        },
        collected_at=_NOW,
    )
    event = GitHubNormalizer().normalize("audit_log", raw)[0]
    assert event.attributes["actor_email"] is None
    assert event.attributes["target_email"] is None
    assert event.attributes["actor_provider_id"] == "1001"
    assert event.attributes["target_provider_id"] == "1005"
    # The logins are still available for display.
    assert event.attributes["attributes"]["actor_login"] == "alice"
    assert event.attributes["attributes"]["target_login"] == "erin"


def test_a_non_dict_audit_data_field_does_not_crash_normalization() -> None:
    raw = RawObject(
        object_type="audit_log",
        provider_id="audit-2",
        payload={
            "action": "org.disable_member_two_factor",
            "created_at": "2026-07-27T10:00:00Z",
            "data": "unexpected",
        },
        collected_at=_NOW,
    )
    event = GitHubNormalizer().normalize("audit_log", raw)[0]
    assert event.attributes["action"] == "mfa.disable"


# -- audit taxonomy ------------------------------------------------


def _audit_event(action: str, data: dict | None = None, **payload):
    raw = _raw("audit_log", "evt", {"action": action, "data": data or {}, **payload})
    return GitHubNormalizer().normalize("audit_log", raw)


@pytest.mark.parametrize(
    ("github_action", "expected"),
    [
        ("org.add_member", "identity.add"),
        ("org.remove_member", "identity.deactivate"),
        ("org.add_outside_collaborator", "identity.guest"),
        ("org.enable_two_factor_requirement", "mfa.enforce"),
        ("team.add_member", "group.member.add"),
        ("team.remove_member", "group.member.remove"),
        ("team.add_repository", "access.grant"),
        ("repo.remove_member", "access.revoke"),
        ("protected_branch.destroy", "branch_protection.disable"),
        ("repository_ruleset.destroy", "branch_protection.disable"),
        ("hook.create", "webhook.create"),
        ("deploy_key.create", "deploy_key.create"),
        ("integration_installation.create", "oauth.app.install"),
        ("integration_installation.repositories_added", "oauth.scope.expand"),
        ("integration_installation.destroy", "oauth.app.revoke"),
        ("personal_access_token.access_granted", "token.grant"),
        ("org.saml_disabled", "sso.change"),
        ("org.ip_allow_list.disable", "config.change"),
        ("repo.secret_scanning_push_protection_disabled", "config.change"),
        ("repo.create", "resource.create"),
        ("repo.destroy", "resource.delete"),
    ],
)
def test_the_curated_taxonomy_maps_each_security_relevant_action(github_action, expected):
    events = _audit_event(github_action)
    assert len(events) == 1
    assert events[0].attributes["action"] == expected


@pytest.mark.parametrize(
    "noise_action",
    [
        "git.clone",
        "git.push",
        "repo.rename",
        "org.update_default_repository_permission_to_read",
        "project.create",
    ],
)
def test_operational_noise_is_dropped_rather_than_stored(noise_action):
    # Curated, not exhaustive: mapping everything would push real signal out of
    # both the event-policy window and the Changes actor overlay.
    assert _audit_event(noise_action) == []


def test_a_role_change_is_read_from_its_payload_not_its_name():
    """`org.update_member` covers promotion and demotion alike."""
    promoted = _audit_event("org.update_member", {"permission": "admin"})
    demoted = _audit_event("org.update_member", {"permission": "member"})

    assert promoted[0].attributes["action"] == "privilege.grant"
    assert demoted[0].attributes["action"] == "privilege.revoke"


def test_a_privileged_grant_to_an_outside_collaborator_is_its_own_action():
    events = _audit_event("org.update_member", {"permission": "admin", "external": True})
    assert events[0].attributes["action"] == "privilege.external"


def test_only_the_visibility_transition_that_exposes_a_repo_is_recorded():
    # `repo.access` fires for every direction; going private is not a finding.
    assert _audit_event("repo.access", {"visibility": "public"})[0].attributes["action"] == ("sharing.external")
    assert _audit_event("repo.access", {"visibility": "private"}) == []


def test_an_unmapped_action_still_surfaces_a_privileged_permission():
    # Whatever GitHub called it, handing someone admin is worth an event.
    events = _audit_event("some.future.action", {"permission": "admin"})
    assert events[0].attributes["action"] == "privilege.grant"


def test_every_mapped_action_has_a_category():
    from kestrel_connector_github.normalizer import (
        _ACTION_CATEGORIES,
        _GITHUB_ACTION_TO_KESTREL,
    )

    # An action with no category silently becomes "other", which the event
    # policies and the actor overlay both key off.
    missing = set(_GITHUB_ACTION_TO_KESTREL.values()) - set(_ACTION_CATEGORIES)
    assert missing == set()


def test_the_payload_detail_a_policy_needs_survives_normalization():
    events = _audit_event(
        "hook.create",
        {"hook_id": 42, "events": ["push"]},
        repo="acme-corp/web-app",
        actor="alice",
    )
    attributes = events[0].attributes["attributes"]
    assert attributes["hook_id"] == 42
    assert attributes["events"] == ["push"]
    assert attributes["repo"] == "acme-corp/web-app"


# -- org security surface ------------------------------------------


def test_actions_permissions_and_workflow_token_scope_become_settings():
    raw = _raw(
        "actions_permission",
        "actions-permissions",
        {
            "enabled_repositories": "all",
            "allowed_actions": "all",
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": True,
        },
    )

    by_key = {o.attributes["key"]: o.attributes for o in GitHubNormalizer().normalize("actions_permission", raw)}

    assert by_key["default_workflow_permissions"]["value"] == "write"
    assert by_key["can_approve_pull_request_reviews"]["value"] is True
    assert by_key["allowed_actions"]["category"] == "security"


def test_a_runner_group_open_to_public_repositories_is_flagged():
    raw = _raw(
        "runner_group",
        "1",
        {"id": 1, "name": "Default", "visibility": "all", "allows_public_repositories": True},
    )

    by_key = {o.attributes["key"]: o.attributes for o in GitHubNormalizer().normalize("runner_group", raw)}

    assert by_key["actions_runner_group_public_repos:1"]["value"] is True
    assert by_key["actions_runner_group_visibility:1"]["value"] == "all"


def test_an_installed_app_becomes_an_oauth_application_with_scopes():
    """GitHub emitted no oauth_* objects at all ."""
    raw = _raw(
        "installed_app",
        "7001",
        {
            "id": 7001,
            "app_slug": "deploy-bot",
            "account": {"login": "acme-corp"},
            "permissions": {"contents": "write", "metadata": "read"},
        },
    )

    objects = GitHubNormalizer().normalize("installed_app", raw)
    app = next(o for o in objects if o.kind == "oauth_application")
    scopes = {o.attributes["scope_name"]: o.attributes for o in objects if o.kind == "oauth_scope"}

    assert app.attributes["name"] == "deploy-bot"
    assert app.attributes["publisher"] == "acme-corp"
    # Not claimed verified: GitHub does not expose Marketplace verification here.
    assert app.attributes["is_verified"] is None
    assert scopes["contents:write"]["is_sensitive"] is True
    assert scopes["metadata:read"]["is_sensitive"] is False


def test_a_read_permission_on_a_credential_surface_is_still_sensitive():
    # Read access to org secrets or members is an exposure even without write.
    raw = _raw(
        "installed_app",
        "7003",
        {"id": 7003, "app_slug": "auditor", "permissions": {"members": "read"}},
    )

    scopes = [o for o in GitHubNormalizer().normalize("installed_app", raw) if o.kind == "oauth_scope"]
    assert scopes[0].attributes["is_sensitive"] is True


def test_a_custom_org_role_with_management_permissions_is_privileged():
    privileged = _raw(
        "custom_org_role",
        "9901",
        {"id": 9901, "name": "Repo Admin", "permissions": ["manage_repository_settings"]},
    )
    plain = _raw("custom_org_role", "9902", {"id": 9902, "name": "Reader", "permissions": ["read_code"]})

    assert GitHubNormalizer().normalize("custom_org_role", privileged)[0].attributes["is_privileged"] is True
    assert GitHubNormalizer().normalize("custom_org_role", plain)[0].attributes["is_privileged"] is False


def test_a_webhook_setting_records_the_host_and_tls_state():
    raw = _raw(
        "org_webhook",
        "5501",
        {
            "id": 5501,
            "active": True,
            "events": ["push"],
            "config": {"url_host": "hooks.example.test", "url_scheme": "https", "insecure_ssl": "1"},
        },
    )

    value = GitHubNormalizer().normalize("org_webhook", raw)[0].attributes["value"]

    assert value["host"] == "hooks.example.test"
    assert value["insecure_ssl"] is True


def test_a_ruleset_that_only_evaluates_keeps_its_enforcement_visible():
    raw = _raw(
        "org_ruleset",
        "8801",
        {"id": 8801, "name": "main-protection", "target": "branch", "enforcement": "evaluate"},
    )

    value = GitHubNormalizer().normalize("org_ruleset", raw)[0].attributes["value"]
    assert value["enforcement"] == "evaluate"


def test_an_sso_credential_records_when_it_was_last_used():
    raw = _raw(
        "credential_authorization",
        "30001",
        {
            "credential_id": 30001,
            "login": "dave",
            "credential_type": "personal access token",
            "scopes": ["repo"],
            "credential_accessed_at": "2026-01-15T09:00:00Z",
        },
    )

    value = GitHubNormalizer().normalize("credential_authorization", raw)[0].attributes["value"]
    assert value["login"] == "dave"
    assert value["last_accessed_at"] == "2026-01-15T09:00:00Z"


def test_a_pending_admin_invitation_keeps_its_role_visible():
    raw = _raw(
        "org_invitation",
        "6601",
        {"id": 6601, "login": "newhire", "role": "admin", "inviter": {"login": "alice"}},
    )

    value = GitHubNormalizer().normalize("org_invitation", raw)[0].attributes["value"]
    assert value["role"] == "admin"
    assert value["inviter"] == "alice"


def test_every_collected_object_type_has_a_normalizer():
    """A collected type with no normalizer raises mid-run, after the API calls."""
    from kestrel_connector_github.collector import OBJECT_TYPES
    from kestrel_connector_github.normalizer import _MODULE_NORMALIZERS

    normalizer = GitHubNormalizer()
    missing = [
        object_type
        for object_type in OBJECT_TYPES
        if object_type not in _MODULE_NORMALIZERS and not hasattr(normalizer, f"_normalize_{object_type}")
    ]
    assert missing == []


# `GET /orgs/{org}` returns the five settings below and no others. The fixture
# used to carry `saml_enabled`, `is_ip_allow_list_enabled`,
# `oauth_app_restrictions_enabled`, and `audit_log_streaming_configured`, none of
# which that endpoint returns -- SAML configuration and the IP allow list are
# GraphQL-only, as docs/posture-baselines/github.md already records. Nothing read
# them, so unlike Slack and Google Workspace no false finding escaped, but they
# are the same seed: a fixture asserting the API returns something it does not.
# extended added web_commit_signoff_required, members_can_create_private_repositories,
# members_can_create_pages, and members_can_create_public_pages. The test below uses the
# original five-field payload to confirm that only fields present in the payload
# produce settings (the new fields are omitted → not emitted).
_ORG_CORE_SETTING_KEYS = {
    "two_factor_requirement_enabled",
    "default_repository_permission",
    "members_can_create_repositories",
    "members_can_create_public_repositories",
    "members_can_fork_private_repositories",
}


def test_org_settings_come_only_from_documented_rest_fields():
    payload = {
        "login": "acme-corp",
        "id": 1,
        "node_id": "O_1",
        "name": "Acme Corp",
        "description": "Acme",
        "plan": {"name": "enterprise"},
        "two_factor_requirement_enabled": False,
        "default_repository_permission": "write",
        "members_can_create_repositories": True,
        "members_can_create_public_repositories": True,
        "members_can_fork_private_repositories": False,
    }
    keys = {
        o.attributes["key"]
        for o in GitHubNormalizer().normalize("organization", _raw("organization", "acme-corp", payload))
        if o.kind == "setting"
    }
    assert keys == _ORG_CORE_SETTING_KEYS


def test_org_web_commit_signoff_is_emitted_when_present():
    """Extended: web_commit_signoff_required is now a documented org setting."""
    payload = {
        "two_factor_requirement_enabled": True,
        "web_commit_signoff_required": True,
    }
    keys = {
        o.attributes["key"]
        for o in GitHubNormalizer().normalize("organization", _raw("organization", "acme-corp", payload))
        if o.kind == "setting"
    }
    assert "web_commit_signoff_required" in keys


def test_graphql_only_org_fields_do_not_become_settings():
    """Guard the seed: even if a payload carried them, they are not org settings."""
    payload = {
        "login": "acme-corp",
        "two_factor_requirement_enabled": True,
        "saml_enabled": True,
        "is_ip_allow_list_enabled": True,
        "oauth_app_restrictions_enabled": True,
        "audit_log_streaming_configured": True,
    }
    keys = {
        o.attributes["key"]
        for o in GitHubNormalizer().normalize("organization", _raw("organization", "acme-corp", payload))
        if o.kind == "setting"
    }
    for invented in (
        "saml_enabled",
        "is_ip_allow_list_enabled",
        "oauth_app_restrictions_enabled",
        "audit_log_streaming_configured",
    ):
        assert invented not in keys


# -- Extended: new normalizer tests ---------------------------------------


def test_ip_allow_list_disabled_emits_false_enabled_flag():
    raw = _raw("org_ip_allow_list", "ip-allow-list", {"enabled_setting": "DISABLED", "entries": []})

    objects = GitHubNormalizer().normalize("org_ip_allow_list", raw)

    enabled_setting = next(o for o in objects if o.attributes["key"] == "ip_allow_list_enabled")
    assert enabled_setting.attributes["value"] is False


def test_ip_allow_list_enabled_emits_true_enabled_flag():
    entry = {"id": "EI_1", "allowListValue": "203.0.113.0/24", "isActive": True, "name": "Corp"}
    raw = _raw("org_ip_allow_list", "ip-allow-list", {"enabled_setting": "ENABLED", "entries": [entry]})

    objects = GitHubNormalizer().normalize("org_ip_allow_list", raw)

    enabled_setting = next(o for o in objects if o.attributes["key"] == "ip_allow_list_enabled")
    assert enabled_setting.attributes["value"] is True
    entries_setting = next(o for o in objects if o.attributes["key"] == "ip_allow_list_entries")
    assert len(entries_setting.attributes["value"]) == 1


def test_ip_allow_list_none_setting_emits_none_value():
    """When GraphQL returns no ipAllowListEnabledSetting, value is None (not Enterprise Cloud)."""
    raw = _raw("org_ip_allow_list", "ip-allow-list", {"enabled_setting": None, "entries": []})

    objects = GitHubNormalizer().normalize("org_ip_allow_list", raw)

    enabled_setting = next(o for o in objects if o.attributes["key"] == "ip_allow_list_enabled")
    assert enabled_setting.attributes["value"] is None


def test_copilot_policy_emits_public_code_suggestions_setting():
    raw = _raw(
        "copilot_policy",
        "copilot-policy",
        {"public_code_suggestions": "allow", "seat_management_setting": "assign_selected"},
    )

    objects = GitHubNormalizer().normalize("copilot_policy", raw)

    keys = {o.attributes["key"] for o in objects}
    assert "copilot_public_code_suggestions" in keys
    assert "copilot_seat_management_setting" in keys
    allow_setting = next(o for o in objects if o.attributes["key"] == "copilot_public_code_suggestions")
    assert allow_setting.attributes["value"] == "allow"


def test_copilot_seat_with_no_activity_is_normalized():
    raw = _raw(
        "copilot_seat",
        "bob",
        {
            "assignee": {"login": "bob", "id": 2},
            "last_activity_at": None,
            "last_activity_editor": None,
            "created_at": "2026-01-10T09:00:00Z",
        },
    )

    objects = GitHubNormalizer().normalize("copilot_seat", raw)

    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["login"] == "bob"
    assert value["last_activity_at"] is None


def test_approved_pat_emits_flattened_permissions():
    raw = _raw(
        "approved_pat",
        "7801",
        {
            "id": 7801,
            "owner": {"login": "carol"},
            "repository_selection": "all",
            "permissions": {
                "organization": {"administration": "write"},
                "repository": {"contents": "read"},
            },
            "access_granted_at": "2026-09-01T10:00:00Z",
        },
    )

    objects = GitHubNormalizer().normalize("approved_pat", raw)

    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["owner"] == "carol"
    perms = value["permissions"]
    admin_perm = next((p for p in perms if p["scope"] == "organization" and p["name"] == "administration"), None)
    assert admin_perm is not None
    assert admin_perm["level"] == "write"


def test_dependabot_alert_count_is_repo_scoped():
    repo = {"id": 9001, "name": "web-app", "full_name": "acme/web-app"}
    raw = _raw("dependabot_alert", "9001", {"repo": repo, "open_alert_count": 3})

    objects = GitHubNormalizer().normalize("dependabot_alert", raw)

    assert len(objects) == 1
    setting = objects[0]
    assert setting.attributes["key"] == "repo_open_dependabot_alerts"
    assert setting.attributes["value"] == 3
    assert setting.attributes["subject_ref"] == "9001"


def test_repo_vulnerability_alerts_enabled_is_normalized():
    repo = {"id": 9001, "name": "web-app", "full_name": "acme/web-app"}
    raw = _raw("repo_vulnerability_alerts", "9001", {"repo": repo, "enabled": True})

    objects = GitHubNormalizer().normalize("repo_vulnerability_alerts", raw)

    assert len(objects) == 1
    assert objects[0].attributes["key"] == "repo_vulnerability_alerts_enabled"
    assert objects[0].attributes["value"] is True


def test_repo_vulnerability_alerts_disabled_is_normalized():
    repo = {"id": 9001, "name": "web-app", "full_name": "acme/web-app"}
    raw = _raw("repo_vulnerability_alerts", "9001", {"repo": repo, "enabled": False})

    objects = GitHubNormalizer().normalize("repo_vulnerability_alerts", raw)

    assert objects[0].attributes["value"] is False


def test_repo_code_scanning_configured_emits_state_and_languages():
    repo = {"id": 9001, "name": "web-app", "full_name": "acme/web-app"}
    raw = _raw(
        "repo_code_scanning",
        "9001",
        {"repo": repo, "state": "configured", "languages": ["python"], "query_suite": "default"},
    )

    objects = GitHubNormalizer().normalize("repo_code_scanning", raw)

    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["state"] == "configured"
    assert value["languages"] == ["python"]


def test_org_package_public_from_private_repo_is_flagged():
    raw = _raw(
        "org_package",
        "container:my-app",
        {
            "name": "my-app",
            "package_type": "container",
            "visibility": "public",
            "repository": {"name": "web-app", "private": True},
        },
    )

    objects = GitHubNormalizer().normalize("org_package", raw)

    assert len(objects) == 1
    value = objects[0].attributes["value"]
    assert value["visibility"] == "public"
    assert value["repository_private"] is True
    # Category should signal sharing concern
    assert objects[0].attributes["category"] == "sharing"
