# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Drift steps applied on top of the generated fixture tree.

The old demo carried one dict of per-file mutations keyed by hardcoded fixture
filenames and provider ids (`user_roles_00ugrace000000000002.json`). That
cannot survive generated data, where ids are assigned at generation time.

A step here is a function over the whole staged fixtures directory. It looks
entities up by the thing that is stable -- the persona's email -- and edits
whatever file actually holds them. Steps return the operator-facing notes
`demo change` prints.

Steps are ordered oldest-first and are meant to be applied cumulatively: step N
assumes steps 0..N-1 already ran, exactly as a real tenant drifts.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kestrel.demo.generate import okta_role_assignee
from kestrel.demo.personas import build_roster

# A step mutates the staged fixture tree in place and returns its drift notes.
Step = Callable[[Path], list[str]]


def _read(path: Path) -> Any:
    return json.loads(path.read_text()) if path.exists() else None


def _write(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _find_by_email(rows: list[dict[str, Any]], email: str, *keys: str) -> dict[str, Any] | None:
    """First row whose email matches, looking in each candidate location."""
    for row in rows:
        for key in keys:
            value: Any = row
            for part in key.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if isinstance(value, str) and value.lower() == email.lower():
                return row
    return None


def _find_by_login(rows: list[dict[str, Any]], email: str) -> dict[str, Any] | None:
    """Resolve a GitHub row through the roster when the row has no email."""
    persona = next((p for p in build_roster() if p.email.lower() == email.lower()), None)
    if persona is None:
        return None
    login = persona.github_login()
    return next((r for r in rows if r.get("login") == login), None)


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


def github_promote_member_to_org_admin(email: str) -> Step:
    def step(root: Path) -> list[str]:
        admins_path = root / "members_admin.json"
        members_path = root / "members_member.json"
        admins = _read(admins_path) or []
        members = _read(members_path) or []
        person = _find_by_email(members, email, "email")
        if person is None:
            return []
        _write(members_path, [m for m in members if m["id"] != person["id"]])
        _write(admins_path, [*admins, person])
        return [f"{person['login']} promoted to organization admin"]

    return step


def github_grant_repo_admin(email: str, repo: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / f"repo_collaborators_{repo}.json"
        rows = _read(path)
        if rows is None:
            return []
        # Outside collaborators are not org members, so they live in their own
        # file -- and they are exactly who this step is usually about.
        candidates = (
            (_read(root / "members_member.json") or [])
            + (_read(root / "members_admin.json") or [])
            + (_read(root / "outside_collaborators.json") or [])
        )
        person = _find_by_email(candidates, email, "email")
        if person is None:
            # Outside-collaborator rows carry no email, because the real GitHub
            # endpoint does not return one. Resolve through the roster instead
            # of inventing an address the live API would never send.
            person = _find_by_login(candidates, email)
        if person is None or any(r["id"] == person["id"] for r in rows):
            return []
        _write(
            path,
            [
                *rows,
                {
                    **person,
                    "role_name": "admin",
                    "permissions": {
                        "admin": True,
                        "maintain": True,
                        "push": True,
                        "triage": True,
                        "pull": True,
                    },
                },
            ],
        )
        return [f"{person['login']} granted admin on {repo}"]

    return step


def github_reduce_repo_permission(repo: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / f"repo_collaborators_{repo}.json"
        rows = _read(path)
        if not rows:
            return []
        target = next((r for r in rows if r.get("role_name") == "admin"), None)
        if target is None:
            return []
        target["role_name"] = "read"
        target["permissions"] = {
            "admin": False,
            "maintain": False,
            "push": False,
            "triage": False,
            "pull": True,
        }
        _write(path, rows)
        return [f"{target['login']} reduced from admin to read on {repo}"]

    return step


def github_enable_setting(setting: str, label: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / "org.json"
        org = _read(path)
        if org is None or org.get(setting) is True:
            return []
        org[setting] = True
        _write(path, org)
        return [label]

    return step


def github_remove_from_team(team_slug: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / f"team_members_{team_slug}.json"
        rows = _read(path)
        if not rows or len(rows) < 2:
            return []
        removed = rows[-1]
        _write(path, rows[:-1])
        return [f"{removed['login']} removed from {team_slug}"]

    return step


def github_offboard_member(email: str) -> Step:
    """Drop someone from the org entirely -- an `identity_removed` change.

    Offboarding has to be *complete*. GitHub never returns a team member or a
    repository collaborator who is no longer an org member, and neither can the
    fixtures: a membership row pointing at an identity the run did not collect
    is a dangling reference, and the upsert raises on it rather than silently
    dropping the edge.
    """

    def step(root: Path) -> list[str]:
        removed: dict[str, Any] | None = None
        for name in ("members_member.json", "members_admin.json", "members_2fa_disabled.json"):
            path = root / name
            rows = _read(path) or []
            person = _find_by_email(rows, email, "email")
            if person is not None:
                removed = person
                _write(path, [r for r in rows if r["id"] != person["id"]])
        if removed is None:
            return []

        for path in sorted(root.glob("team_members_*.json")) + sorted(root.glob("repo_collaborators_*.json")):
            rows = _read(path) or []
            remaining = [r for r in rows if r.get("id") != removed["id"]]
            if len(remaining) != len(rows):
                _write(path, remaining)
        return [f"{removed['login']} removed from the organization"]

    return step


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


def slack_install_overscoped_app(name: str, installer_email: str) -> Step:
    def step(root: Path) -> list[str]:
        approved_path = root / "approved_apps.json"
        installs_path = root / "installations.json"
        approved = _read(approved_path) or []
        installs = _read(installs_path) or []
        users = _read(root / "users.json") or []
        installer = _find_by_email(users, installer_email, "profile.email")
        if installer is None or any(a["name"] == name for a in approved):
            return []
        app_id = f"A0{name.upper().replace(' ', '')[:10]}"
        approved.append(
            {
                "app_id": app_id,
                "name": name,
                "publisher": "AnalyticsCo",
                "is_app_directory_approved": False,
                "is_internal": False,
                "installer_user_id": installer["id"],
                "developer_type": {"type": "third_party"},
                "scopes": {
                    "bot": ["channels:history", "groups:history", "files:read"],
                    "user": ["users:read.email"],
                },
            }
        )
        installs.append(
            {
                "app_id": app_id,
                "user_id": installer["id"],
                "date_installed": "2026-08-09T22:14:00Z",
                "last_active": "2026-08-10T06:02:00Z",
            }
        )
        _write(approved_path, approved)
        _write(installs_path, installs)
        return [f"over-scoped app '{name}' authorized by {installer['name']}"]

    return step


def slack_expand_app_scopes() -> Step:
    """Add a sensitive scope to an already-installed app (`oauth_scope_expanded`)."""

    def step(root: Path) -> list[str]:
        path = root / "approved_apps.json"
        apps = _read(path) or []
        target = next((a for a in apps if "im:history" not in a.get("scopes", {}).get("bot", [])), None)
        if target is None:
            return []
        target["scopes"]["bot"] = [*target["scopes"].get("bot", []), "im:history"]
        _write(path, apps)
        return [f"'{target['name']}' scopes expanded to include im:history"]

    return step


def slack_promote_to_admin(email: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / "users.json"
        users = _read(path) or []
        person = _find_by_email(users, email, "profile.email")
        if person is None or person.get("is_admin"):
            return []
        person["is_admin"] = True
        _write(path, users)
        return [f"{person['real_name']} promoted to Slack workspace admin"]

    return step


def slack_connect_external_org(team_id: str, team_name: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / "external_teams.json"
        teams = _read(path) or []
        if any(t["team_id"] == team_id for t in teams):
            return []
        teams.append(
            {
                "team_id": team_id,
                "team_name": team_name,
                "team_domain": team_name.lower().replace(" ", ""),
                "public_channel_count": 2,
                "private_channel_count": 1,
                "connection_status": "CONNECTED",
                "last_active_timestamp": 1718656058,
                "is_sponsored": False,
            }
        )
        _write(path, teams)
        return [f"Slack Connect established with {team_name}"]

    return step


# ---------------------------------------------------------------------------
# Okta
# ---------------------------------------------------------------------------


def okta_promote_to_super_admin(email: str) -> Step:
    def step(root: Path) -> list[str]:
        users = _read(root / "users.json") or []
        person = _find_by_email(users, email, "profile.email", "profile.login")
        if person is None:
            return []
        _write(
            root / f"user_roles_{person['id']}.json",
            [
                {
                    "id": f"rol-sa-{person['id'][-6:]}",
                    "type": "SUPER_ADMIN",
                    "status": "ACTIVE",
                    "assignmentType": "USER",
                }
            ],
        )
        # The collector only reads roles for users /iam/assignees lists. With
        # no assignee file it walks every user, so the role is found anyway;
        # creating the file here would hide every other role holder.
        assignees_path = root / "role_assignees.json"
        assignees = _read(assignees_path)
        if isinstance(assignees, dict):
            rows = assignees.setdefault("value", [])
            if not any(row.get("id") == person["id"] for row in rows):
                rows.append(okta_role_assignee(person["id"]))
                _write(assignees_path, assignees)
        name = person["profile"]["email"]
        return [f"{name} promoted to Okta Super Administrator"]

    return step


def okta_deactivate_mfa(email: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / "users.json"
        users = _read(path) or []
        person = _find_by_email(users, email, "profile.email")
        if person is None or not person.get("factors"):
            return []
        person["factors"] = []
        _write(path, users)
        factor_file = root / f"user_factors_{person['id']}.json"
        if factor_file.exists():
            _write(factor_file, [])
        return [f"{person['profile']['email']} MFA factors removed"]

    return step


def okta_deprovision_user(email: str) -> Step:
    def step(root: Path) -> list[str]:
        path = root / "users.json"
        users = _read(path) or []
        person = _find_by_email(users, email, "profile.email")
        if person is None or person.get("status") == "DEPROVISIONED":
            return []
        person["status"] = "DEPROVISIONED"
        _write(path, users)
        return [f"{person['profile']['email']} deprovisioned"]

    return step


def okta_enable_threat_insight() -> Step:
    """Flip a tenant security setting -- a `config_drift` change."""

    def step(root: Path) -> list[str]:
        path = root / "threat_insight.json"
        config = _read(path)
        if config is None or config.get("action") != "none":
            return []
        config["action"] = "audit"
        _write(path, config)
        return ["Okta ThreatInsight switched from none to audit"]

    return step


def github_add_to_team(email: str, team_slug: str) -> Step:
    """`group_member_added`."""

    def step(root: Path) -> list[str]:
        path = root / f"team_members_{team_slug}.json"
        rows = _read(path)
        if rows is None:
            return []
        members = (_read(root / "members_member.json") or []) + (_read(root / "members_admin.json") or [])
        person = _find_by_email(members, email, "email")
        if person is None or any(r["id"] == person["id"] for r in rows):
            return []
        _write(path, [*rows, person])
        return [f"{person['login']} added to {team_slug}"]

    return step


def github_grant_repo_read(email: str, repo: str) -> Step:
    """`access_granted` -- a plain, non-privileged grant."""

    def step(root: Path) -> list[str]:
        path = root / f"repo_collaborators_{repo}.json"
        rows = _read(path)
        if rows is None:
            return []
        members = (_read(root / "members_member.json") or []) + (_read(root / "members_admin.json") or [])
        person = _find_by_email(members, email, "email")
        if person is None or any(r["id"] == person["id"] for r in rows):
            return []
        _write(
            path,
            [
                *rows,
                {
                    **person,
                    "role_name": "read",
                    "permissions": {
                        "admin": False,
                        "maintain": False,
                        "push": False,
                        "triage": False,
                        "pull": True,
                    },
                },
            ],
        )
        return [f"{person['login']} granted read on {repo}"]

    return step


def github_escalate_repo_permission(email: str, repo: str) -> Step:
    """`privilege_escalated` -- an existing grant moving read/write -> admin."""

    def step(root: Path) -> list[str]:
        path = root / f"repo_collaborators_{repo}.json"
        rows = _read(path) or []
        members = (_read(root / "members_member.json") or []) + (_read(root / "members_admin.json") or [])
        person = _find_by_email(members, email, "email")
        if person is None:
            return []
        row = next((r for r in rows if r["id"] == person["id"]), None)
        if row is None or row.get("role_name") == "admin":
            return []
        row["role_name"] = "admin"
        row["permissions"] = {
            "admin": True,
            "maintain": True,
            "push": True,
            "triage": True,
            "pull": True,
        }
        _write(path, rows)
        return [f"{row['login']} escalated to admin on {repo}"]

    return step


def github_revoke_repo_access(repo: str) -> Step:
    """`access_revoked`."""

    def step(root: Path) -> list[str]:
        path = root / f"repo_collaborators_{repo}.json"
        rows = _read(path)
        if not rows:
            return []
        # Pick a non-admin collaborator on purpose: removing an admin grant
        # classifies as `admin_revoked`, which is a different beat and one the
        # timeline already covers elsewhere.
        removed = next((r for r in rows if r.get("role_name") != "admin"), None)
        if removed is None:
            return []
        _write(path, [r for r in rows if r["id"] != removed["id"]])
        return [f"{removed['login']} access revoked on {repo}"]

    return step


def slack_uninstall_app() -> Step:
    """`oauth_app_revoked`."""

    def step(root: Path) -> list[str]:
        approved_path = root / "approved_apps.json"
        installs_path = root / "installations.json"
        approved = _read(approved_path) or []
        installs = _read(installs_path) or []
        if len(approved) < 2:
            return []
        removed = approved[-1]
        _write(approved_path, approved[:-1])
        _write(installs_path, [i for i in installs if i["app_id"] != removed["app_id"]])
        return [f"'{removed['name']}' uninstalled"]

    return step


def github_onboard_member(login: str, name: str, email: str) -> Step:
    """`identity_added` -- a brand-new person joining the org."""

    def step(root: Path) -> list[str]:
        path = root / "members_member.json"
        rows = _read(path) or []
        if any(r.get("login") == login for r in rows):
            return []
        # Ids have to stay unique against the generated roster, which starts at
        # 1000 and counts up; 90000 is well clear of it.
        new_id = 90000 + len(rows)
        _write(
            path,
            [
                *rows,
                {
                    "login": login,
                    "id": new_id,
                    "node_id": f"U_{new_id}",
                    "type": "User",
                    "site_admin": False,
                    "name": name,
                    "email": email,
                },
            ],
        )
        return [f"{login} joined the organization"]

    return step


# ---------------------------------------------------------------------------
# The timeline
# ---------------------------------------------------------------------------


# Personas the steps reference by email. These are roster anchors, so they are
# stable across regenerations.
def gws_suspend_user(email: str) -> Step:
    """Suspend a Workspace account -- the mail half of an offboarding."""

    def step(root: Path) -> list[str]:
        path = root / "users.json"
        users = _read(path) or []
        person = _find_by_email(users, email, "primaryEmail")
        if person is None or person.get("suspended"):
            return []
        person["suspended"] = True
        _write(path, users)
        return [f"{person['primaryEmail']} suspended in Google Workspace"]

    return step


def gws_open_group_to_external_members(group_name: str) -> Step:
    """Flip a group to accept members from outside the domain."""

    def step(root: Path) -> list[str]:
        groups = _read(root / "groups.json") or []
        group = next((g for g in groups if str(g.get("name", "")).lower() == group_name.lower()), None)
        if group is None:
            return []
        path = root / f"group_settings_{group['email']}.json"
        settings = _read(path)
        if settings is None or settings.get("allowExternalMembers") == "true":
            return []
        settings["allowExternalMembers"] = "true"
        _write(path, settings)
        return [f"{group['email']} now allows external members"]

    return step


def gws_grant_super_admin(email: str) -> Step:
    """Give someone Super Admin: the highest-privilege grant in Workspace."""

    def step(root: Path) -> list[str]:
        users = _read(root / "users.json") or []
        person = _find_by_email(users, email, "primaryEmail")
        if person is None:
            return []
        path = root / "role_assignments.json"
        assignments = _read(path) or []
        if any(a.get("assignedTo") == person["id"] and a.get("roleId") == "300000000000001" for a in assignments):
            return []
        assignments.append(
            {
                "kind": "admin#directory#roleAssignment",
                "roleAssignmentId": f"4{len(assignments) + 900:020d}",
                "roleId": "300000000000001",
                "assignedTo": person["id"],
                "scopeType": "CUSTOMER",
            }
        )
        _write(path, assignments)
        if not person.get("isAdmin"):
            person["isAdmin"] = True
            _write(root / "users.json", users)
        return [f"{person['primaryEmail']} granted Google Workspace Super Admin"]

    return step


def gws_consent_risky_app(email: str) -> Step:
    """A user consents to a third-party app with Gmail and Drive scopes."""

    def step(root: Path) -> list[str]:
        users = _read(root / "users.json") or []
        person = _find_by_email(users, email, "primaryEmail")
        if person is None:
            return []
        path = root / f"user_tokens_{person['id']}.json"
        tokens = _read(path) or []
        client_id = "7000-inboxsidekick.apps.googleusercontent.com"
        if any(t.get("clientId") == client_id for t in tokens):
            return []
        tokens.append(
            {
                "kind": "admin#directory#token",
                "clientId": client_id,
                "displayText": "Inbox Sidekick",
                "anonymous": True,
                "nativeApp": False,
                "userKey": person["id"],
                "scopes": [
                    "https://mail.google.com/",
                    "https://www.googleapis.com/auth/drive",
                    "https://www.googleapis.com/auth/contacts",
                ],
            }
        )
        _write(path, tokens)
        return [f"{person['primaryEmail']} authorized Inbox Sidekick (Gmail + Drive)"]

    return step


GRACE = "grace@acme.example.com"
ALAN = "alan@acme.example.com"
ADA = "ada@acme.example.com"
KATHERINE = "katherine@acme.example.com"
CONTRACTOR = "contractor@vendor.example.com"

# Ordered oldest-first, and deliberately mixed in direction and significance.
# The privilege grants, the sharing flip, and the over-scoped install are what
# should rank at the top of `/changes`; the membership churn and the demotion
# should sort below them. A feed where everything is HIGH ranks nothing.
TIMELINE: tuple[tuple[str, dict[str, list[Step]]], ...] = (
    (
        "Contractor onboarding",
        {
            "github": [
                github_grant_repo_admin(CONTRACTOR, "customer-pii-export"),
                github_add_to_team(ALAN, "security-team"),
                github_grant_repo_read(ADA, "terraform-production"),
                github_grant_repo_read(GRACE, "customer-pii-export"),
            ],
            "slack": [slack_connect_external_org("T0NEWVENDOR", "New Vendor Ltd")],
        },
    ),
    (
        "Quarterly access drift",
        {
            "github": [github_remove_from_team("platform-team")],
            "okta": [okta_promote_to_super_admin(ALAN)],
        },
    ),
    (
        "Shadow IT install",
        {
            "slack": [slack_install_overscoped_app("Team Analytics", ALAN)],
            "okta": [okta_enable_threat_insight()],
        },
    ),
    # Katherine leaves Okta and GitHub, and her Workspace account is suspended
    # -- but nothing touches Slack. That surviving account is the subject of
    # `cross-app-departed-still-has-access`, and the reason the demo can show a
    # finding no single admin console produces.
    (
        "Offboarding",
        {
            "okta": [okta_deprovision_user(KATHERINE)],
            "github": [
                github_offboard_member(KATHERINE),
                github_onboard_member("noor-haddad", "Noor Haddad", "noor.haddad@acme.example.com"),
            ],
            "google_workspace": [gws_suspend_user(KATHERINE)],
        },
    ),
    (
        "MFA regression",
        {
            "okta": [okta_deactivate_mfa(ADA)],
            "github": [
                github_enable_setting(
                    "members_can_create_public_repositories",
                    "public repository creation enabled org-wide",
                )
            ],
        },
    ),
    (
        "Scope creep",
        {
            "google_workspace": [gws_consent_risky_app(ALAN), gws_open_group_to_external_members("Finance")],
            "slack": [slack_expand_app_scopes(), slack_uninstall_app()],
            "github": [
                github_reduce_repo_permission("terraform-production"),
                github_revoke_repo_access("customer-pii-export"),
            ],
        },
    ),
    # Last, and deliberately so. The newest step has to *open* findings, not
    # resolve them: it is what the default 7-day Changes window and the 0-7 day
    # finding-age bucket show, and both look broken when the most recent thing
    # that happened was someone leaving. Alan is elevated in Okta at step 1 and
    # again here in GitHub and Slack, which is the cross-app escalation story.
    (
        "Privilege expansion",
        {
            "github": [
                github_promote_member_to_org_admin(ALAN),
                github_grant_repo_admin(GRACE, "secrets-vault"),
                github_escalate_repo_permission(ADA, "terraform-production"),
            ],
            "slack": [slack_promote_to_admin(ALAN)],
            "google_workspace": [gws_grant_super_admin(ALAN)],
        },
    ),
)


def steps_for(tenant: str, upto: int | None = None) -> list[Step]:
    """Every step for one tenant, oldest first, through step index `upto`."""
    limit = len(TIMELINE) if upto is None else min(upto + 1, len(TIMELINE))
    collected: list[Step] = []
    for _, by_tenant in TIMELINE[:limit]:
        collected.extend(by_tenant.get(tenant, []))
    return collected


def tenants_at(index: int) -> list[str]:
    """Tenants that actually drift at step `index`.

    Re-syncing a tenant nothing happened to costs a full collection pass and
    produces a zero-diff run, which is both slow and misleading in the run
    history -- a real tenant does not re-sync because a different SaaS changed.
    """
    if not 0 <= index < len(TIMELINE):
        return []
    return sorted(name for name, steps in TIMELINE[index][1].items() if steps)


def apply_steps(root: Path, steps: list[Step]) -> list[str]:
    """Apply steps in order to a staged fixture tree, collecting drift notes."""
    notes: list[str] = []
    for step in steps:
        notes.extend(step(root))
    return notes
