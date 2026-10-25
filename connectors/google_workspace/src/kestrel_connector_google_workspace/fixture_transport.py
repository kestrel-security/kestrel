# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Builds a FixtureTransport preconfigured for this connector's bundled
fixtures/ dataset (a synthetic "acme.example.com" Workspace domain), used by
unit tests and by `kestrel connector validate` to prove the connector works
without live credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureStatus, FixtureTransport

from kestrel_connector_google_workspace.client import (
    admin_activities_path,
    alerts_list_path,
    chromeos_devices_path,
    customer_path,
    domain_path,
    domains_list_path,
    drive_activities_path,
    drive_permissions_path,
    drives_list_path,
    group_members_path,
    group_settings_path,
    groups_activities_path,
    groups_list_path,
    inbound_sso_assignments_path,
    inbound_sso_profiles_path,
    login_activities_path,
    mobile_activities_path,
    mobile_devices_path,
    org_units_path,
    policies_list_path,
    role_assignments_path,
    roles_list_path,
    saml_activities_path,
    user_accounts_activities_path,
    user_tokens_path,
    users_list_path,
)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

DOMAIN = "acme.example.com"
# Retained for callers that import them. The mapping derives the real lists
# from fixture *content* so a generated tree (the demo seed) works unchanged --
# and so a fixture file whose id was never added to a constant cannot go
# unnoticed: an unmapped signature raises rather than resolving to nothing.
GROUP_IDS = ["200000000000000000001", "200000000000000000002"]
DRIVE_IDS = ["500000000000001", "500000000000002"]


def _ids_from(fixtures_dir: Path, filename: str, key: str, fallback: list[str]) -> list[str]:
    path = fixtures_dir / filename
    if not path.exists():
        return list(fallback)
    data = json.loads(path.read_text())
    rows = data if isinstance(data, list) else data.get(key) or []
    ids = [str(row["id"]) for row in rows if isinstance(row, dict) and row.get("id")]
    return ids or list(fallback)


def _user_ids(fixtures_dir: Path) -> list[str]:
    path = fixtures_dir / "users.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    rows = data if isinstance(data, list) else data.get("users", [])
    return [str(row["id"]) for row in rows if isinstance(row, dict) and row.get("id")]


def _group_emails(fixtures_dir: Path) -> list[str]:
    path = fixtures_dir / "groups.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    rows = data if isinstance(data, list) else data.get("groups", [])
    return [str(row["email"]) for row in rows if isinstance(row, dict) and row.get("email")]


def _mapping(domain: str = DOMAIN, fixtures_dir: Path | None = None) -> dict[str, str | FixtureStatus]:
    resolved = fixtures_dir or FIXTURES_DIR
    mapping: dict[str, str | FixtureStatus] = {
        f"GET {domain_path(domain)}": "domain.json",
        f"GET {domains_list_path()}": "domains.json",
        f"GET {org_units_path()}": "org_units.json",
        f"GET {users_list_path()}": "users.json",
        f"GET {users_list_path(max_results=1)}": "users.json",
        f"GET {groups_list_path()}": "groups.json",
        f"GET {groups_list_path(max_results=1)}": "groups.json",
        f"GET {roles_list_path()}": "roles.json",
        f"GET {roles_list_path(max_results=1)}": "roles.json",
        f"GET {role_assignments_path()}": "role_assignments.json",
        f"GET {drives_list_path()}": "shared_drives.json",
        f"GET {drives_list_path(page_size=1)}": "shared_drives.json",
        f"GET {login_activities_path()}": "login_activities.json",
        f"GET {login_activities_path(max_results=1)}": "login_activities.json",
        # v0.2 additions
        f"GET {customer_path()}": "customer.json",
        f"GET {policies_list_path()}": "policies.json",
        f"GET {mobile_devices_path()}": "mobile_devices.json",
        f"GET {chromeos_devices_path()}": "chromeos_devices.json",
        f"GET {alerts_list_path()}": "alerts.json",
        f"GET {inbound_sso_profiles_path()}": "inbound_sso_profiles.json",
        f"GET {inbound_sso_assignments_path()}": "inbound_sso_assignments.json",
        f"GET {admin_activities_path()}": "admin_activities.json",
        f"GET {drive_activities_path()}": "drive_activities.json",
        f"GET {saml_activities_path()}": "saml_activities.json",
        f"GET {user_accounts_activities_path()}": "user_accounts_activities.json",
        f"GET {groups_activities_path()}": "groups_activities.json",
        f"GET {mobile_activities_path()}": "mobile_activities.json",
    }
    for group_id in _ids_from(resolved, "groups.json", "groups", GROUP_IDS):
        mapping[f"GET {group_members_path(group_id)}"] = f"group_members_{group_id}.json"
    for drive_id in _ids_from(resolved, "shared_drives.json", "drives", DRIVE_IDS):
        mapping[f"GET {drive_permissions_path(drive_id)}"] = f"drive_permissions_{drive_id}.json"
    for email in _group_emails(resolved):
        mapping[f"GET {group_settings_path(email)}"] = f"group_settings_{email}.json"
    for user_id in _user_ids(resolved):
        # A user without a tokens file has granted nothing -- not a gap.
        token_file = resolved / f"user_tokens_{user_id}.json"
        mapping[f"GET {user_tokens_path(user_id)}"] = token_file.name if token_file.exists() else "user_tokens_empty.json"
    return mapping


def build_fixture_transport(domain: str = DOMAIN, fixtures_dir: str | Path | None = None) -> FixtureTransport:
    """`fixtures_dir` overrides the bundled dataset with an edited copy, which
    is how change-detection tests and the demo script stage a "someone changed
    something between syncs" tenant."""
    resolved = Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR
    return FixtureTransport(
        fixtures_dir=resolved,
        mapping=_mapping(domain, resolved),
        # Cursored polls append `&startTime=<watermark>`, which changes every
        # run and so cannot be an exact-match signature.
        volatile_params={"startTime"},
    )
