# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""FixtureTransport for the bundled Acme Slack workspace fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureStatus, FixtureTransport

from kestrel_connector_slack.client import AUDIT_PAGE_LIMIT, CONVERSATIONS_SEARCH_LIMIT, PAGE_LIMIT

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

TEAM_ID = "T0ACMEWORK"
ENTERPRISE_ID = "E0ACMEGRID"
# Retained for callers that import it. The mapping derives the real list from
# fixture content so a generated dataset (the demo seed) works unchanged, and so
# a usergroup file whose id was never added to a constant cannot go unnoticed --
# an unmapped signature resolves to nothing rather than failing.
USERGROUP_IDS = ["S0ENGINEERING", "S0SECURITY"]


def _ids_from(fixtures_dir: Path, filename: str, fallback: list[str]) -> list[str]:
    path = fixtures_dir / filename
    if not path.exists():
        return list(fallback)
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return list(fallback)
    ids = [str(row["id"]) for row in data if isinstance(row, dict) and row.get("id")]
    return ids or list(fallback)


def _usergroup_ids(fixtures_dir: Path) -> list[str]:
    return _ids_from(fixtures_dir, "usergroups.json", USERGROUP_IDS)


def _workspace_ids(fixtures_dir: Path, team_id: str) -> list[str]:
    """Grid workspaces. The collector reads settings for each one, so every
    workspace in `workspaces.json` needs its own mapped signature."""
    return _ids_from(fixtures_dir, "workspaces.json", [team_id])


def _mapping(team_id: str, fixtures_dir: Path) -> dict[str, str | FixtureStatus]:
    mapping: dict[str, str | FixtureStatus] = {
        f"GET /team.info?team={team_id}": "team.json",
        "GET /users.list": "users.json",
        f"GET /users.list?limit={PAGE_LIMIT}": "users.json",
        "GET /users.list?limit=1": "users.json",
        f"GET /users.list?team_id={team_id}&limit={PAGE_LIMIT}": "users.json",
        f"GET /users.list?team_id={team_id}&limit=1": "users.json",
        "GET /usergroups.list?include_users=false": "usergroups.json",
        f"GET /usergroups.list?include_users=false&limit={PAGE_LIMIT}": "usergroups.json",
        "GET /usergroups.list?include_users=false&limit=1": "usergroups.json",
        (f"GET /usergroups.list?team_id={team_id}&include_users=false&limit={PAGE_LIMIT}"): "usergroups.json",
        (f"GET /usergroups.list?team_id={team_id}&include_users=false&limit=1"): "usergroups.json",
        f"GET /admin.apps.approved.list?team_id={team_id}": "approved_apps.json",
        f"GET /admin.apps.approved.list?team_id={team_id}&limit={PAGE_LIMIT}": "approved_apps.json",
        f"GET /admin.apps.approved.list?team_id={team_id}&limit=1": "approved_apps.json",
        f"GET /admin.apps.activities.list?team_id={team_id}&limit={PAGE_LIMIT}": "app_activities.json",
        f"GET /admin.apps.restricted.list?team_id={team_id}&limit={PAGE_LIMIT}": "restricted_apps.json",
        f"GET /admin.apps.requests.list?team_id={team_id}&limit={PAGE_LIMIT}": "app_requests.json",
        f"GET /admin.teams.list?limit={PAGE_LIMIT}": "workspaces.json",
        "GET /admin.teams.list?limit=1": "workspaces.json",
        # Per-workspace settings are registered below, including this one.
        f"GET /admin.roles.listAssignments?limit={PAGE_LIMIT}": "role_assignments.json",
        "GET /admin.roles.listAssignments?limit=1": "role_assignments.json",
        f"GET /team.externalTeams.list?limit={PAGE_LIMIT}": "external_teams.json",
        (
            f"POST /admin.conversations.search?team_ids={team_id}"
            f"&limit={CONVERSATIONS_SEARCH_LIMIT}&search_channel_types=external_shared"
        ): "shared_channels.json",
        # Legacy fixture key (pre-fix) — keep until callers migrate.
        (
            f"POST /admin.conversations.search?team_id={team_id}&limit={PAGE_LIMIT}&search_channel_types=external_shared"
        ): "shared_channels.json",
        "POST /admin.audit.anomaly.allow.getItem": "anomaly_allowlist.json",
        "POST /admin.users.session.getSettings": "session_settings.json",
        (f"GET /conversations.list?types=public_channel%2Cprivate_channel&exclude_archived=true&limit={PAGE_LIMIT}"): (
            "channels.json"
        ),
        f"GET /logs?limit={AUDIT_PAGE_LIMIT}": "audit_log.json",
        "GET /logs?limit=1": "audit_log.json",
        # Release C — Enterprise depth families.
        "POST /admin.auth.policy.getEntities": "sso_policies.json",
        f"GET /admin.barriers.list?limit={PAGE_LIMIT}": "information_barriers.json",
        "GET /admin.barriers.list?limit=1": "information_barriers.json",
        f"GET /admin.workflows.search?limit={PAGE_LIMIT}": "workflows.json",
        "GET /admin.workflows.search?limit=1": "workflows.json",
        f"GET /admin.invites.invited.list?limit={PAGE_LIMIT}": "invite_requests.json",
        f"GET /admin.invites.invited.list?limit={PAGE_LIMIT}&enterprise_id={ENTERPRISE_ID}": "invite_requests.json",
        "GET /admin.analytics.getFile?type=member": "member_analytics.json",
        "GET /admin.analytics.getFile?type=member&metadata_only=true": "member_analytics.json",
        # Channel retention: same fixture for any channel (POST body not in path).
        "POST /admin.conversations.getCustomRetention": "channel_retention.json",
    }
    for workspace_id in _workspace_ids(fixtures_dir, team_id):
        # Prefer a per-workspace file; fall back to the single shared one the
        # bundled single-workspace fixture set ships.
        per_workspace = f"workspace_settings_{workspace_id}.json"
        filename = per_workspace if (fixtures_dir / per_workspace).exists() else "workspace_settings.json"
        mapping[f"POST /admin.teams.settings.info?team_id={workspace_id}"] = filename
    for channel_id in _ids_from(fixtures_dir, "channels.json", []):
        # A channel without a members file has no readable membership -- the
        # empty answer, not a gap.
        members_file = f"channel_members_{channel_id}.json"
        filename = members_file if (fixtures_dir / members_file).exists() else "channel_members_empty.json"
        mapping[f"GET /conversations.members?channel={channel_id}&limit={PAGE_LIMIT}"] = filename
    for usergroup_id in _usergroup_ids(fixtures_dir):
        mapping[f"GET /usergroups.users.list?usergroup={usergroup_id}"] = f"usergroup_users_{usergroup_id}.json"
        mapping[f"GET /usergroups.users.list?usergroup={usergroup_id}&limit={PAGE_LIMIT}"] = (
            f"usergroup_users_{usergroup_id}.json"
        )
        mapping[f"GET /usergroups.users.list?usergroup={usergroup_id}&team_id={team_id}&limit={PAGE_LIMIT}"] = (
            f"usergroup_users_{usergroup_id}.json"
        )
    return mapping


def build_fixture_transport(team_id: str = TEAM_ID, fixtures_dir: str | Path | None = None) -> FixtureTransport:
    """`fixtures_dir` overrides the bundled dataset with an edited copy, which
    is how change-detection tests and the demo script stage a "someone changed
    something between syncs" tenant."""
    resolved = Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR
    return FixtureTransport(
        fixtures_dir=resolved,
        mapping=_mapping(team_id, resolved),
        # An incremental Audit Logs poll appends `&oldest=<unix>`; see
        # FixtureTransport.volatile_params.
        volatile_params={"oldest"},
    )
