# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""FixtureTransport for the bundled Acme Okta org fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureStatus, FixtureTransport

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

ORG_URL = "https://acme.okta.com"
USER_IDS = [
    "00uada00000000000001",
    "00ugrace000000000002",
    "00ualan0000000000003",
    "00ucontractor000004",
    "00uformer00000000005",
]
GROUP_IDS = ["00gengineering000001", "00gsecurity00000002"]
APP_IDS = ["0oaslack000000000001", "0oagithub00000000002", "0oainternal000000003", "0oabookmark000000004"]

# Client list paths use limit=200; health probes use limit=1.
_LIST_LIMITS = (1, 200)


def _entity_ids(fixtures_dir: Path, filename: str, fallback: list[str]) -> list[str]:
    path = fixtures_dir / filename
    if not path.exists():
        return list(fallback)
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return list(fallback)
    ids = [str(row["id"]) for row in data if isinstance(row, dict) and row.get("id")]
    return ids or list(fallback)


def _per_entity(fixtures_dir: Path, filename: str) -> str:
    """A per-entity fixture if it exists, else the shared empty sentinel.

    Deriving this from the filesystem rather than a hardcoded dict is what fixed
    a real bug: five shipped fixture files were absent from the old
    `_FACTOR_FILES` / `_USER_ROLE_FILES` maps, so their signatures silently
    resolved to `empty_list.json` and the data was unreachable -- invisible,
    because an unmapped-but-defaulted signature does not fail.
    """
    return filename if (fixtures_dir / filename).exists() else "empty_list.json"


# Policy types collected beyond PASSWORD and MFA_ENROLL, and the
# fixture that answers each.
_POLICY_TYPE_FIXTURES: dict[str, str] = {
    "ACCESS_POLICY": "access_policies.json",
    "OKTA_SIGN_ON": "sign_on_policies.json",
    "PROFILE_ENROLLMENT": "profile_enrollment_policies.json",
    "IDP_DISCOVERY": "idp_discovery_policies.json",
    # extended policy types
    "ENTITY_RISK": "entity_risk_policies.json",
    "POST_AUTH_SESSION": "post_auth_session_policies.json",
}


def _policy_ids(fixtures_dir: Path) -> list[str]:
    """Every policy id across the shipped policy fixtures.

    Derived from file contents rather than a constant, for the same reason
    `_per_entity` is: a policy added to a fixture but missing from a hardcoded
    list would have its rules silently resolve to nothing, which reads exactly
    like a policy that enforces nothing.
    """
    ids: list[str] = []
    filenames = [
        *_POLICY_TYPE_FIXTURES.values(),
        "password_policies.json",
        "mfa_enroll_policies.json",
    ]
    for filename in filenames:
        path = fixtures_dir / filename
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        if not isinstance(data, list):
            continue
        ids.extend(str(row["id"]) for row in data if isinstance(row, dict) and row.get("id"))
    return ids


def _mapping(fixtures_dir: Path) -> dict[str, str | FixtureStatus]:
    mapping: dict[str, str | FixtureStatus] = {
        "GET /api/v1/org": "org.json",
        "GET /api/v1/threats/configuration": "threat_insight.json",
        # Extended: single-page endpoints (no pagination limit variant)
        "GET /api/v1/behaviors": _per_entity(fixtures_dir, "behaviors.json"),
        "GET /api/v1/logStreams": _per_entity(fixtures_dir, "log_streams.json"),
        "GET /api/v1/device-assurances": _per_entity(fixtures_dir, "device_assurances.json"),
        "GET /api/v1/eventHooks": _per_entity(fixtures_dir, "event_hooks.json"),
        "GET /api/v1/inlineHooks": _per_entity(fixtures_dir, "inline_hooks.json"),
        "GET /api/v1/authenticators": _per_entity(fixtures_dir, "authenticators.json"),
    }
    # Users holding admin roles. A tree without the file reproduces an org
    # where /iam/assignees is unavailable, so the collector walks every user.
    assignees = fixtures_dir / "role_assignees.json"
    for limit in _LIST_LIMITS:
        mapping[f"GET /api/v1/iam/assignees/users?limit={limit}"] = (
            assignees.name if assignees.exists() else FixtureStatus(404)
        )
    for limit in _LIST_LIMITS:
        mapping[f"GET /api/v1/users?limit={limit}"] = "users.json"
        mapping[f"GET /api/v1/groups?limit={limit}"] = "groups.json"
        mapping[f"GET /api/v1/apps?limit={limit}"] = "apps.json"
        mapping[f"GET /api/v1/policies?type=PASSWORD&limit={limit}"] = "password_policies.json"
        mapping[f"GET /api/v1/policies?type=MFA_ENROLL&limit={limit}"] = "mfa_enroll_policies.json"
        mapping[f"GET /api/v1/policies?type=OKTA_SIGN_ON&limit={limit}"] = "signon_policies.json"
        mapping[f"GET /api/v1/policies?type=SESSION&limit={limit}"] = "session_policies.json"
        mapping[f"GET /api/v1/authenticators?limit={limit}"] = "authenticators.json"
        mapping[f"GET /api/v1/zones?limit={limit}"] = "network_zones.json"
        mapping[f"GET /api/v1/api-tokens?limit={limit}"] = "api_tokens.json"
        # -- authentication and session policy surface -----------
        for policy_type, filename in _POLICY_TYPE_FIXTURES.items():
            mapping[f"GET /api/v1/policies?type={policy_type}&limit={limit}"] = filename
    mapping["GET /api/v1/authenticators"] = "authenticators.json"
    mapping["GET /api/v1/device-assurances"] = "device_assurances.json"
    # -- perimeter and automation surface ------------------------
    for limit in _LIST_LIMITS:
        mapping[f"GET /api/v1/zones?limit={limit}"] = "network_zones.json"
        mapping[f"GET /api/v1/trustedOrigins?limit={limit}"] = "trusted_origins.json"
        mapping[f"GET /api/v1/idps?limit={limit}"] = "identity_providers.json"
        mapping[f"GET /api/v1/groups/rules?limit={limit}"] = "group_rules.json"
        # Extended: paginated endpoints
        mapping[f"GET /api/v1/behaviors?limit={limit}"] = _per_entity(fixtures_dir, "behaviors.json")
        mapping[f"GET /api/v1/logStreams?limit={limit}"] = _per_entity(fixtures_dir, "log_streams.json")
        mapping[f"GET /api/v1/devices?limit={limit}"] = _per_entity(fixtures_dir, "devices.json")
        mapping[f"GET /api/v1/authorizationServers?limit={limit}"] = _per_entity(fixtures_dir, "authorization_servers.json")
        mapping[f"GET /api/v1/iam/roles?limit={limit}"] = _per_entity(fixtures_dir, "iam_roles.json")
        mapping[f"GET /api/v1/iam/resource-sets?limit={limit}"] = _per_entity(fixtures_dir, "resource_sets.json")
    for policy_id in _policy_ids(fixtures_dir):
        rules = _per_entity(fixtures_dir, f"policy_rules_{policy_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/policies/{policy_id}/rules?limit={limit}"] = rules
    mapping["GET /api/v1/logs?limit=1"] = "system_log.json"
    mapping["GET /api/v1/logs?limit=200&sortOrder=DESCENDING"] = "system_log.json"

    for user_id in _entity_ids(fixtures_dir, "users.json", USER_IDS):
        factors = _per_entity(fixtures_dir, f"user_factors_{user_id}.json")
        roles = _per_entity(fixtures_dir, f"user_roles_{user_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/users/{user_id}/factors?limit={limit}"] = factors
            mapping[f"GET /api/v1/users/{user_id}/roles?limit={limit}"] = roles

    for group_id in _entity_ids(fixtures_dir, "groups.json", GROUP_IDS):
        group_users = _per_entity(fixtures_dir, f"group_users_{group_id}.json")
        group_roles = _per_entity(fixtures_dir, f"group_roles_{group_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/groups/{group_id}/users?limit={limit}"] = group_users
            mapping[f"GET /api/v1/groups/{group_id}/roles?limit={limit}"] = group_roles

    for app_id in _entity_ids(fixtures_dir, "apps.json", APP_IDS):
        app_users = _per_entity(fixtures_dir, f"app_users_{app_id}.json")
        app_groups = _per_entity(fixtures_dir, f"app_groups_{app_id}.json")
        app_grants = _per_entity(fixtures_dir, f"app_grants_{app_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/apps/{app_id}/users?limit={limit}"] = app_users
            mapping[f"GET /api/v1/apps/{app_id}/groups?limit={limit}"] = app_groups
            mapping[f"GET /api/v1/apps/{app_id}/grants?limit={limit}"] = app_grants

    # Extended: per-entity sub-resources for authorization servers and IAM roles
    for server_id in _entity_ids(fixtures_dir, "authorization_servers.json", []):
        as_policies = _per_entity(fixtures_dir, f"as_policies_{server_id}.json")
        as_scopes = _per_entity(fixtures_dir, f"as_scopes_{server_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/authorizationServers/{server_id}/policies?limit={limit}"] = as_policies
            mapping[f"GET /api/v1/authorizationServers/{server_id}/scopes?limit={limit}"] = as_scopes

    for role_id in _entity_ids(fixtures_dir, "iam_roles.json", []):
        role_perms = _per_entity(fixtures_dir, f"iam_role_permissions_{role_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/iam/roles/{role_id}/permissions?limit={limit}"] = role_perms

    for device_id in _entity_ids(fixtures_dir, "devices.json", []):
        device_users = _per_entity(fixtures_dir, f"device_users_{device_id}.json")
        for limit in _LIST_LIMITS:
            mapping[f"GET /api/v1/devices/{device_id}/users?limit={limit}"] = device_users

    return mapping


def build_fixture_transport(org_url: str = ORG_URL, fixtures_dir: str | Path | None = None) -> FixtureTransport:
    """`fixtures_dir` overrides the bundled dataset with an edited copy, which
    is how change-detection tests and the demo script stage a "someone changed
    something between syncs" tenant."""
    _ = org_url  # reserved for future per-tenant fixture roots
    resolved = Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR
    return FixtureTransport(
        fixtures_dir=resolved,
        mapping=_mapping(resolved),
        # An incremental System Log poll appends `&since=<timestamp>`, which no
        # exact-match signature can cover. Stripping it resolves the cursored
        # call to the same fixture as the full one.
        volatile_params={"since"},
    )
