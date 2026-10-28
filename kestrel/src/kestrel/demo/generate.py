# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic fixture generation for the demo tenants.

The shipped `connectors/*/fixtures/` trees stay small and hand-readable -- they
are the CI contract artifact and they feed `kestrel init --seed`. This module
writes a much larger tree at `demo up` time into a temp directory, handed to
each connector through the `build_fixture_transport(fixtures_dir=...)` override
that already exists for change-coverage validation.

Everything is driven by one seeded `random.Random`, so two `demo up` runs on two
machines produce byte-identical fixtures and therefore an identical demo.

Volume is only half the point. The generators also guarantee *coverage*: enough
admins without MFA, external collaborators with write access, dormant accounts,
and over-scoped apps that every shipped policy has something to fire on, and
enough edge variety that no Explore filter chip yields an empty graph.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from kestrel.demo.personas import (
    DEFAULT_SEED,
    Archetype,
    Persona,
    build_roster,
    roster_for,
)

GITHUB_ORG_LOGIN = "acme-corp"

# Repo naming: a believable mix of services, libraries, and the one repo whose
# name makes an over-permissive grant obviously bad on a slide.
_REPO_PREFIXES = (
    "web",
    "api",
    "billing",
    "identity",
    "search",
    "notify",
    "ingest",
    "ledger",
    "gateway",
    "scheduler",
    "reporting",
    "mobile",
    "infra",
    "docs",
    "design",
)
_REPO_SUFFIXES = ("app", "service", "worker", "sdk", "ui", "lib", "tools", "config")

_SENSITIVE_REPOS = ("secrets-vault", "terraform-production", "customer-pii-export")

_TEAM_NAMES = (
    "Platform Team",
    "Security Team",
    "Payments",
    "Identity",
    "Data Platform",
    "Frontend",
    "Mobile",
    "SRE",
    "Growth",
    "Support Engineering",
    "ML",
    "Docs",
)


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _assert_unique(kind: str, ids: list[str] | list[int]) -> None:
    """Fail loudly on duplicate provider ids.

    Upserts key on `provider_object_id`, so two entities sharing an id silently
    become one -- the row count comes out short and nothing errors. The one time
    it *does* error is deep in a unique constraint on a child table, which is a
    terrible place to learn about it.
    """
    if len(set(ids)) != len(ids):
        seen: set[Any] = set()
        dupes = sorted({str(i) for i in ids if i in seen or seen.add(i)})  # type: ignore[func-returns-value]
        raise ValueError(f"duplicate {kind} ids in generated fixtures: {dupes[:5]}")


def _github_user(persona: Persona, user_id: int) -> dict[str, Any]:
    return {
        "login": persona.github_login(),
        "id": user_id,
        "node_id": f"U_{user_id}",
        "type": "Bot" if persona.archetype is Archetype.SERVICE_ACCOUNT else "User",
        "site_admin": False,
        "name": persona.display_name,
        "email": persona.email,
    }


def _permissions(level: str) -> dict[str, bool]:
    return {
        "admin": level == "admin",
        "maintain": level in {"admin", "maintain"},
        "push": level in {"admin", "maintain", "write"},
        "triage": level != "read",
        "pull": True,
    }


def generate_github(
    target: Path,
    personas: list[Persona],
    *,
    rng: random.Random,
    now: datetime,
    repo_count: int = 40,
    team_count: int = 12,
) -> None:
    """Write a full GitHub fixture tree for the given roster."""
    cast = roster_for(personas, "github")
    members = [p for p in cast if not p.is_external]
    outside = [p for p in cast if p.is_external]

    ids = {p.key: 1000 + index for index, p in enumerate(cast)}
    _assert_unique("github user", list(ids.values()))

    admins = [p for p in members if p.is_admin]
    plain = [p for p in members if not p.is_admin]

    _write(
        target / "org.json",
        {
            "id": 123456,
            "login": GITHUB_ORG_LOGIN,
            "name": "Acme Corp",
            "plan": {"name": "enterprise"},
            # Deliberately non-compliant: these three are what the shipped
            # org-settings policies fire on.
            "two_factor_requirement_enabled": False,
            "default_repository_permission": "write",
            "members_can_create_repositories": True,
            "members_can_create_public_repositories": False,
            "members_can_fork_private_repositories": True,
        },
    )

    _write(target / "members_admin.json", [_github_user(p, ids[p.key]) for p in admins])
    _write(target / "members_member.json", [_github_user(p, ids[p.key]) for p in plain])
    # The SSO-linked identity is what a live tenant actually exposes for email;
    # the generated org is SAML-enabled so the fixture path matches production.
    _write(
        target / "saml_external_identities.json",
        {
            "data": {
                "organization": {
                    "samlIdentityProvider": {
                        "externalIdentities": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [
                                {
                                    "user": {"login": p.github_login()},
                                    "samlIdentity": {"nameId": p.email},
                                    "scimIdentity": {"username": p.email},
                                }
                                for p in admins + plain
                            ],
                        }
                    }
                }
            }
        },
    )
    _write(
        target / "members_2fa_disabled.json",
        [_github_user(p, ids[p.key]) for p in members if not p.has_mfa],
    )
    _write(
        target / "outside_collaborators.json",
        [
            {
                "login": p.github_login(),
                "id": ids[p.key],
                "node_id": f"U_{ids[p.key]}",
                "type": "User",
            }
            for p in outside
        ],
    )

    # -- repositories ------------------------------------------------------
    repos: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for name in _SENSITIVE_REPOS:
        seen_names.add(name)
    while len(seen_names) < repo_count:
        seen_names.add(f"{rng.choice(_REPO_PREFIXES)}-{rng.choice(_REPO_SUFFIXES)}")

    for index, name in enumerate(sorted(seen_names)):
        repo_id = 9000 + index
        # ~15% public, ~15% internal -- public repos are what make branch
        # protection and "members can create public repos" matter.
        roll = rng.random()
        visibility = "public" if roll < 0.15 else ("internal" if roll < 0.30 else "private")
        repos.append(
            {
                "id": repo_id,
                "node_id": f"R_{repo_id}",
                "name": name,
                "full_name": f"{GITHUB_ORG_LOGIN}/{name}",
                "private": visibility != "public",
                "visibility": visibility,
                "archived": rng.random() < 0.08,
                "fork": rng.random() < 0.05,
                "default_branch": "main",
                # GHAS is enterprise-gated in reality, so most repos have it
                # off -- which is what makes the enablement policies matter.
                "security_and_analysis": {
                    "advanced_security": {"status": "enabled" if rng.random() < 0.35 else "disabled"},
                    "secret_scanning": {"status": "enabled" if rng.random() < 0.4 else "disabled"},
                    "secret_scanning_push_protection": {"status": "enabled" if rng.random() < 0.25 else "disabled"},
                    "dependabot_security_updates": {"status": "enabled" if rng.random() < 0.5 else "disabled"},
                },
            }
        )
    _assert_unique("github repo", [r["name"] for r in repos])
    _assert_unique("github repo id", [r["id"] for r in repos])
    _write(target / "repos.json", repos)

    # -- teams -------------------------------------------------------------
    team_names = list(_TEAM_NAMES)[:team_count]
    teams: list[dict[str, Any]] = []
    for index, team_name in enumerate(team_names):
        team_id = 5000 + index
        slug = team_name.lower().replace(" ", "-")
        teams.append(
            {
                "id": team_id,
                "node_id": f"T_{team_id}",
                "slug": slug,
                "name": team_name,
                "description": f"{team_name} members",
                "permission": rng.choice(["pull", "push", "push", "admin"]),
            }
        )
    _assert_unique("github team", [t["slug"] for t in teams])
    _write(target / "teams.json", teams)

    for team in teams:
        size = rng.randint(3, max(4, len(members) // 4))
        team_members = rng.sample(members, min(size, len(members)))
        _write(
            target / f"team_members_{team['slug']}.json",
            [_github_user(p, ids[p.key]) for p in team_members],
        )

        repo_sample = rng.sample(repos, rng.randint(2, min(8, len(repos))))
        team_repos = []
        for repo in repo_sample:
            level = rng.choice(["read", "write", "write", "admin"])
            team_repos.append({**repo, "permissions": _permissions(level)})
        _write(target / f"team_repos_{team['slug']}.json", team_repos)

    # -- direct collaborators ---------------------------------------------
    # Every repo needs a file or the mapping resolves to a missing fixture.
    for repo in repos:
        collaborators: list[dict[str, Any]] = []
        for persona in rng.sample(members, rng.randint(0, 3)):
            level = rng.choice(["read", "write", "admin"])
            collaborators.append(
                {
                    **_github_user(persona, ids[persona.key]),
                    "role_name": level,
                    "permissions": _permissions(level),
                }
            )
        # Guarantee the beat: an outside collaborator holding admin on a
        # sensitive repo is the finding operators are meant to notice.
        if repo["name"] in _SENSITIVE_REPOS and outside:
            guest = outside[hash(repo["name"]) % len(outside)]
            collaborators.append(
                {
                    "login": guest.github_login(),
                    "id": ids[guest.key],
                    "node_id": f"U_{ids[guest.key]}",
                    "type": "User",
                    "role_name": "admin",
                    "permissions": _permissions("admin"),
                }
            )
        _write(target / f"repo_collaborators_{repo['name']}.json", collaborators)

    _write(target / "audit_log.json", _github_audit_log(cast, ids, repos, rng=rng, now=now))
    _write_github_org_surface(target, cast, ids, teams, rng=rng, now=now)
    _write_github_repo_posture(target, repos, rng=rng, now=now)


def _write_github_repo_posture(
    target: Path,
    repos: list[dict[str, Any]],
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """Per-repository posture for every generated repository.

    Written for all of them, not just the deep-scan tier: the tier is decided
    at collection time from live data, and a fixture set has to answer whatever
    it selects. Values vary by repository so the demo has real spread rather
    than one uniform answer -- some unprotected, some with force pushes
    allowed, a few with writable deploy keys and open secret-scanning alerts.
    """
    for repo in repos:
        name = repo["name"]
        public = repo.get("visibility") == "public"
        # Public repos are more likely to be looked after; private ones drift.
        protected = public or rng.random() < 0.55
        if protected:
            _write(
                target / f"repo_branch_protection_{name}.json",
                {
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 2 if public else 1,
                        "dismiss_stale_reviews": rng.random() < 0.5,
                        "require_code_owner_reviews": public,
                    },
                    "enforce_admins": {"enabled": rng.random() < 0.4},
                    "required_status_checks": {"strict": public, "contexts": ["ci"]},
                    "allow_force_pushes": {"enabled": rng.random() < 0.25},
                    "allow_deletions": {"enabled": False},
                    "required_linear_history": {"enabled": public},
                },
            )
        # else: no file, and the fixture transport reproduces GitHub's 404.

        rulesets = []
        if rng.random() < 0.3:
            rulesets.append(
                {
                    "id": 8900 + repo["id"] % 1000,
                    "name": "main-protection",
                    "target": "branch",
                    "enforcement": rng.choice(["active", "evaluate", "disabled"]),
                }
            )
        _write(target / f"repo_rulesets_{name}.json", rulesets)

        hooks = []
        if rng.random() < 0.25:
            hooks.append(
                {
                    "id": 6100 + repo["id"] % 1000,
                    "active": True,
                    "events": ["push"],
                    "config": {
                        "url": f"https://ci.example.test/{name}/hook-not-real",
                        "insecure_ssl": "1" if rng.random() < 0.3 else "0",
                    },
                }
            )
        _write(target / f"repo_webhooks_{name}.json", hooks)

        keys = []
        if rng.random() < 0.2:
            keys.append(
                {
                    "id": 7200 + repo["id"] % 1000,
                    "title": f"{name}-deploy",
                    "read_only": rng.random() < 0.5,
                    "created_at": _iso(now - timedelta(days=rng.randint(60, 800))),
                    "last_used": None,
                }
            )
        _write(target / f"repo_deploy_keys_{name}.json", keys)

        environments = []
        if rng.random() < 0.35:
            environments.append(
                {
                    "id": 8300 + repo["id"] % 1000,
                    "name": "production",
                    "protection_rules": ([{"id": 1, "type": "required_reviewers"}] if rng.random() < 0.5 else []),
                }
            )
        _write(
            target / f"repo_environments_{name}.json",
            {"total_count": len(environments), "environments": environments},
        )

        _write(
            target / f"repo_actions_permissions_{name}.json",
            {"enabled": True, "allowed_actions": rng.choice(["all", "all", "selected"])},
        )

        open_alerts = rng.randint(0, 3) if rng.random() < 0.3 else 0
        _write(
            target / f"repo_secret_scanning_alerts_{name}.json",
            [{"number": index + 1, "state": "open"} for index in range(open_alerts)],
        )


def _write_github_org_surface(
    target: Path,
    cast: list[Persona],
    ids: dict[str, int],
    teams: list[dict[str, Any]],
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """org security surface, deliberately imperfect.

    Every family the connector collects gets a file, or fixture mode raises on
    a mapped signature with no data. The values are chosen so the demo tenant
    has something to find: a permissive Actions policy, a runner group open to
    public repositories, a webhook without TLS verification, an over-permissioned
    App, a ruleset that only evaluates, and a pending admin invitation.
    """
    admins = [p for p in cast if p.is_admin and not p.is_external]
    inviter = admins[0] if admins else cast[0]

    _write(
        target / "actions_permissions.json",
        {"enabled_repositories": "all", "allowed_actions": "all"},
    )
    _write(
        target / "actions_workflow_permissions.json",
        {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
    )
    _write(
        target / "runner_groups.json",
        {
            "total_count": 2,
            "runner_groups": [
                {
                    "id": 1,
                    "name": "Default",
                    "visibility": "all",
                    "allows_public_repositories": True,
                    "default": True,
                },
                {
                    "id": 2,
                    "name": "isolated-build",
                    "visibility": "selected",
                    "allows_public_repositories": False,
                    "default": False,
                },
            ],
        },
    )
    _write(
        target / "self_hosted_runners.json",
        {
            "total_count": 2,
            "runners": [
                {
                    "id": 90 + index,
                    "name": f"build-{index:02d}",
                    "os": "linux",
                    "status": "online" if index == 0 else "offline",
                    "labels": [{"id": 1, "name": "self-hosted"}, {"id": 2, "name": "linux"}],
                }
                for index in range(2)
            ],
        },
    )
    _write(
        target / "actions_secrets.json",
        {
            "total_count": 3,
            "secrets": [
                {"name": name, "visibility": visibility, "created_at": _iso(now)}
                for name, visibility in (
                    ("DEPLOY_TOKEN", "all"),
                    ("NPM_TOKEN", "selected"),
                    ("AWS_ROLE_ARN", "private"),
                )
            ],
        },
    )
    _write(
        target / "actions_variables.json",
        {
            "total_count": 1,
            "variables": [
                {
                    "name": "LEGACY_API_KEY",
                    # Present on purpose: the collector must drop it before the
                    # value ever reaches a RawObject.
                    "value": "demo-value-not-a-real-secret",
                    "visibility": "all",
                    "created_at": _iso(now),
                }
            ],
        },
    )
    _write(
        target / "org_webhooks.json",
        [
            {
                "id": 5501,
                "name": "web",
                "active": True,
                "events": ["push", "repository", "member"],
                "config": {
                    "url": "https://hooks.example.test/services/demo/token-not-real",
                    "content_type": "json",
                    "insecure_ssl": "1",
                },
            }
        ],
    )
    _write(
        target / "installations.json",
        {
            "total_count": 2,
            "installations": [
                {
                    "id": 7001,
                    "app_id": 400,
                    "app_slug": "deploy-bot",
                    "account": {"login": GITHUB_ORG_LOGIN, "type": "Organization"},
                    "target_type": "Organization",
                    "repository_selection": "all",
                    "permissions": {
                        "contents": "write",
                        "metadata": "read",
                        "organization_administration": "read",
                        "secrets": "read",
                    },
                },
                {
                    "id": 7002,
                    "app_id": 401,
                    "app_slug": "readonly-linter",
                    "account": {"login": GITHUB_ORG_LOGIN, "type": "Organization"},
                    "target_type": "Organization",
                    "repository_selection": "selected",
                    "permissions": {"pull_requests": "read"},
                },
            ],
        },
    )
    stale = [p for p in cast if not p.is_admin and not p.is_external][:2]
    _write(
        target / "credential_authorizations.json",
        [
            {
                "credential_id": 30000 + index,
                "login": persona.github_login(),
                "credential_type": "personal access token",
                "scopes": ["repo", "read:org"],
                "credential_authorized_at": _iso(now - timedelta(days=400)),
                "credential_accessed_at": _iso(now - timedelta(days=300 + index * 30)),
            }
            for index, persona in enumerate(stale)
        ],
    )
    _write(
        target / "org_rulesets.json",
        [
            {
                "id": 8801,
                "name": "main-protection",
                "target": "branch",
                # Evaluate mode looks configured and enforces nothing.
                "enforcement": "evaluate",
                "source_type": "Organization",
            }
        ],
    )
    security_team = next((t for t in teams if "security" in str(t.get("slug", "")).lower()), teams[0] if teams else None)
    _write(
        target / "security_managers.json",
        [security_team] if security_team else [],
    )
    _write(
        target / "custom_org_roles.json",
        {
            "total_count": 1,
            "roles": [
                {
                    "id": 9901,
                    "name": "Repo Admin (custom)",
                    "description": "Manage repository settings",
                    "permissions": ["manage_repository_settings", "read_code"],
                }
            ],
        },
    )
    _write(
        target / "org_invitations.json",
        [
            {
                "id": 6601,
                "login": "contractor-pending",
                "email": None,
                "role": "admin",
                "created_at": _iso(now - timedelta(days=21)),
                "inviter": {"login": inviter.github_login(), "id": ids[inviter.key]},
            }
        ],
    )
    _write(
        target / "pat_requests.json",
        [
            {
                "id": 7701,
                "owner": {
                    "login": stale[0].github_login() if stale else inviter.github_login(),
                    "id": ids[stale[0].key] if stale else ids[inviter.key],
                },
                "repository_selection": "all",
                "permissions_added": {"organization": {"members": "read"}},
                "created_at": _iso(now - timedelta(days=3)),
            }
        ],
    )


def _github_audit_log(
    cast: list[Persona],
    ids: dict[str, int],
    repos: list[dict[str, Any]],
    *,
    rng: random.Random,
    now: datetime,
    count: int = 60,
) -> list[dict[str, Any]]:
    """Audit entries spread across 90 days, covering every mapped action.

    Actions are left untagged so they resolve through the normalizer's real
    action map and heuristics rather than a `kestrel_action` shortcut.
    """
    admins = [p for p in cast if p.is_admin] or cast[:1]
    entries: list[dict[str, Any]] = []

    templates: tuple[tuple[str, dict[str, Any]], ...] = (
        ("org.update_member", {"permission": "admin"}),
        ("org.disable_member_two_factor", {}),
        ("oauth_authorization.create", {"application_name": "Shadow CI Bot", "scopes": ["repo", "admin:org"]}),
        ("org.reactivate_member", {"days_dormant": 120}),
        ("repo.add_member", {"permission": "admin", "external": True}),
    )

    for index in range(count):
        action, data = templates[index % len(templates)]
        actor = rng.choice(admins)
        target = rng.choice(cast)
        occurred = now - timedelta(days=rng.randint(0, 89), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        entry: dict[str, Any] = {
            "_document_id": f"audit-{index:04d}",
            "action": action,
            "actor": actor.github_login(),
            "actor_id": ids.get(actor.key),
            "org": GITHUB_ORG_LOGIN,
            "user": target.github_login(),
            "user_id": ids.get(target.key),
            "created_at": _iso(occurred),
            "data": dict(data),
        }
        if action == "repo.add_member":
            entry["repo"] = rng.choice(repos)["name"]
        entries.append(entry)

    # People who have gone quiet everywhere did act once, long ago: without an
    # observation GitHub could only report them as unknown, not dormant.
    for offset, persona in enumerate(p for p in cast if p.archetype is Archetype.DORMANT):
        entries.append(
            {
                "_document_id": f"audit-dormant-{offset:02d}",
                "action": "org.update_member",
                "actor": persona.github_login(),
                "actor_id": ids.get(persona.key),
                "org": GITHUB_ORG_LOGIN,
                "user": persona.github_login(),
                "user_id": ids.get(persona.key),
                "created_at": _iso(now - timedelta(days=200 + offset)),
                "data": {"permission": "read"},
            }
        )

    entries.sort(key=lambda e: e["created_at"])
    return entries


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

SLACK_TEAM_ID = "T0ACMEWORK"
SLACK_ENTERPRISE_ID = "E0ACMEGRID"

_SLACK_GROUPS = (
    "Engineering",
    "Security",
    "Platform",
    "Data",
    "Sales",
    "Support",
    "Finance",
    "People",
    "Incident Response",
    "Design",
)

# Bot scopes that Slack's normalizer flags as sensitive. Apps holding these are
# what make the over-scoped-app policy fire.
_SENSITIVE_BOT_SCOPES = ("channels:history", "groups:history", "files:read", "im:history")
_BENIGN_BOT_SCOPES = ("chat:write", "users:read", "reactions:write", "emoji:read")

_SLACK_APP_NAMES = (
    "Incident Bot",
    "Calendar Sync",
    "Status Page",
    "Deploy Notifier",
    "PagerTree",
    "Standup Buddy",
    "Doc Search",
    "Expense Helper",
    "Recruit Flow",
    "Task Sync",
    "Survey Pulse",
    "Release Radar",
    "Ticket Bridge",
    "Data Digest",
    "Security Watch",
    "Onboarding Bot",
    "Travel Desk",
    "Perf Monitor",
    "Note Taker",
    "Poll Maker",
    "Vendor Portal",
    "Billing Sync",
    "Asset Tracker",
    "Kudos",
    "Meeting Notes",
)

_VENDOR_TEAMS = (
    ("T0VENDOR", "Vendor Co", "vendorco"),
    ("T0PARTNER", "Partner Analytics", "partneranalytics"),
    ("T0AGENCY", "Design Agency", "designagency"),
    ("T0LEGAL", "Outside Counsel", "outsidecounsel"),
)


def _slack_user(persona: Persona, user_id: str) -> dict[str, Any]:
    return {
        "id": user_id,
        "team_id": SLACK_TEAM_ID,
        "name": persona.slack_handle(),
        "deleted": persona.is_disabled,
        "real_name": persona.display_name,
        "is_admin": persona.is_admin,
        "is_owner": persona.archetype is Archetype.ADMIN and persona.key == "ada",
        "is_primary_owner": persona.key == "ada",
        "is_restricted": persona.is_guest_in("slack"),
        "is_ultra_restricted": False,
        "is_bot": persona.archetype is Archetype.SERVICE_ACCOUNT,
        "has_2fa": persona.has_mfa,
        "profile": {"real_name": persona.display_name, "email": persona.email},
        "updated": 1722470400,
    }


def generate_slack(
    target: Path,
    personas: list[Persona],
    *,
    rng: random.Random,
    now: datetime,
    app_count: int = 25,
    channel_count: int = 15,
) -> None:
    """Write a full Slack Enterprise Grid fixture tree for the given roster."""
    cast = roster_for(personas, "slack")
    ids = {p.key: f"U{index:04d}{p.key[:4].upper().replace('-', '')}" for index, p in enumerate(cast)}
    _assert_unique("slack user", list(ids.values()))
    admins = [p for p in cast if p.is_admin] or cast[:1]

    _write(
        target / "team.json",
        {
            "id": SLACK_TEAM_ID,
            "name": "Acme Corp",
            "domain": "acme",
            "email_domain": "acme.example.com",
        },
    )
    _write(
        target / "workspace_settings.json",
        {
            "id": SLACK_TEAM_ID,
            "name": "Acme Corp",
            "domain": "acme",
            "email_domain": "acme.example.com",
            "enterprise_id": SLACK_ENTERPRISE_ID,
            "enterprise_name": "Acme Grid",
            "default_channels": [],
        },
    )
    workspaces = [
        (SLACK_TEAM_ID, "Acme Corp", "acme"),
        ("T0ENG", "Acme Engineering", "acme-eng"),
        ("T0SALES", "Acme Sales", "acme-sales"),
        ("T0LABS", "Acme Labs", "acme-labs"),
    ]
    _write(
        target / "workspaces.json",
        [
            {"id": ws_id, "name": name, "domain": domain, "email_domain": "acme.example.com"}
            for ws_id, name, domain in workspaces
        ],
    )
    # The collector reads settings per workspace, so each needs its own file.
    for ws_id, name, domain in workspaces:
        _write(
            target / f"workspace_settings_{ws_id}.json",
            {
                "id": ws_id,
                "name": name,
                "domain": domain,
                "email_domain": "acme.example.com",
                "enterprise_id": SLACK_ENTERPRISE_ID,
                "enterprise_name": "Acme Grid",
                "default_channels": [],
            },
        )
    _write(target / "users.json", [_slack_user(p, ids[p.key]) for p in cast])
    # Slack applies session duration per account (admin.users.session.getSettings).
    # Staff get a working day; externals and contractors are the long-session gap.
    _write(
        target / "session_settings.json",
        {
            "ok": True,
            "session_settings": [
                {
                    "user_id": ids[p.key],
                    "desktop_app_browser_quit": not p.is_external,
                    "duration": 2592000 if p.is_external else 43200,
                }
                for p in cast
                if not p.is_disabled
            ],
            "no_settings_applied": [],
        },
    )
    _write(target / "anomaly_allowlist.json", {"ok": True, "trusted_cidrs": [], "trusted_asns": []})

    # -- usergroups --------------------------------------------------------
    usergroups: list[dict[str, Any]] = []
    for index, name in enumerate(_SLACK_GROUPS):
        group_id = f"S0{name.upper().replace(' ', '')[:12]}"
        members = rng.sample(cast, rng.randint(3, max(4, len(cast) // 4)))
        usergroups.append(
            {
                "id": group_id,
                "team_id": SLACK_TEAM_ID,
                "name": name,
                "handle": name.lower().replace(" ", "-"),
                "description": f"{name} usergroup",
                "date_create": 1700000000 + index,
                "user_count": len(members),
            }
        )
        _write(
            target / f"usergroup_users_{group_id}.json",
            {"ok": True, "users": [ids[p.key] for p in members]},
        )
    _assert_unique("slack usergroup", [g["id"] for g in usergroups])
    _write(target / "usergroups.json", usergroups)

    # -- org roles ---------------------------------------------------------
    _write(
        target / "role_assignments.json",
        [
            {
                "role_id": "Rl01" if index % 2 == 0 else "Rl0E",
                "entity_id": SLACK_ENTERPRISE_ID if index % 2 == 0 else SLACK_TEAM_ID,
                "user_id": ids[p.key],
                "date_create": 1700000000 + index,
            }
            for index, p in enumerate(admins)
        ],
    )

    # -- apps --------------------------------------------------------------
    approved: list[dict[str, Any]] = []
    for name in _SLACK_APP_NAMES[:app_count]:
        app_id = f"A0{name.upper().replace(' ', '')[:10]}"
        installer = rng.choice(cast)
        internal = rng.random() < 0.3
        # ~35% over-scoped: enough that the policy has real subjects, few
        # enough that the finding still means something.
        sensitive = rng.random() < 0.35
        bot_scopes = list(rng.sample(_BENIGN_BOT_SCOPES, 2))
        if sensitive:
            bot_scopes += list(rng.sample(_SENSITIVE_BOT_SCOPES, rng.randint(1, 3)))
        approved.append(
            {
                "app_id": app_id,
                "name": name,
                "publisher": "Acme Security" if internal else f"{name.split()[0]}Co",
                "is_app_directory_approved": rng.random() < 0.6,
                "is_internal": internal,
                "installer_user_id": ids[installer.key],
                "developer_type": {"type": "internal" if internal else "third_party"},
                "scopes": {
                    "bot": bot_scopes,
                    "user": ["users:read.email"] if sensitive and rng.random() < 0.5 else [],
                },
            }
        )
        installed = now - timedelta(days=rng.randint(5, 400))
        # Slack has no installations API; the approved-app record is where the
        # installer and install date live, and activities carry last-active.
        approved[-1]["date_installed"] = _iso(installed)
        approved[-1]["last_active"] = _iso(now - timedelta(days=rng.randint(0, 120)))
    _assert_unique("slack app", [a["app_id"] for a in approved])
    _write(target / "approved_apps.json", approved)

    _write(
        target / "restricted_apps.json",
        [
            {
                "app": {
                    "id": "A0BLOCKED",
                    "name": "Blocked Exfil Bot",
                    "is_app_directory_approved": False,
                    "developer_type": "third_party",
                },
                "scopes": [{"name": "files:read", "token_type": "bot", "is_sensitive": True}],
                "date_updated": 1700002000,
            },
            {
                "app": {
                    "id": "A0SCRAPER",
                    "name": "Channel Scraper",
                    "is_app_directory_approved": False,
                    "developer_type": "third_party",
                },
                "scopes": [{"name": "channels:history", "token_type": "bot", "is_sensitive": True}],
                "date_updated": 1700002500,
            },
        ],
    )
    _write(
        target / "app_requests.json",
        [
            {
                "id": f"req_{index:03d}",
                "user_id": ids[rng.choice(cast).key],
                "team_id": SLACK_TEAM_ID,
                "app": {"id": f"A0PENDING{index}", "name": f"Pending App {index}"},
                "date_created": 1700003000 + index,
            }
            for index in range(4)
        ],
    )

    # -- Slack Connect -----------------------------------------------------
    _write(
        target / "external_teams.json",
        [
            {
                "team_id": team_id,
                "team_name": team_name,
                "team_domain": domain,
                "public_channel_count": rng.randint(1, 6),
                "private_channel_count": rng.randint(0, 3),
                "connection_status": "CONNECTED",
                "last_active_timestamp": 1718656058,
                "is_sponsored": False,
            }
            for team_id, team_name, domain in _VENDOR_TEAMS
        ],
    )
    _write(
        target / "shared_channels.json",
        [
            {
                "id": f"C0EXT{index:03d}",
                "name": f"ext-{rng.choice(['project', 'support', 'launch', 'review'])}-{index:02d}",
                "is_ext_shared": True,
                "is_shared": True,
                "is_private": rng.random() < 0.3,
                "member_count": rng.randint(4, 40),
                "internal_team_ids": [SLACK_TEAM_ID],
                "connected_team_ids": [rng.choice(_VENDOR_TEAMS)[0]],
            }
            for index in range(channel_count)
        ],
    )

    _write(target / "audit_log.json", _slack_audit_log(cast, ids, rng=rng, now=now))


def _slack_audit_log(
    cast: list[Persona],
    ids: dict[str, str],
    *,
    rng: random.Random,
    now: datetime,
    count: int = 50,
) -> list[dict[str, Any]]:
    admins = [p for p in cast if p.is_admin] or cast[:1]
    actions = (
        "role_change_to_admin",
        "app_scopes_expanded",
        "guest_created",
        "external_shared_channel_connected",
        "app_installed",
        "user_login",  # noise the normalizer drops -- proves the filter works
    )
    entries: list[dict[str, Any]] = []
    for index in range(count):
        action = actions[index % len(actions)]
        actor = rng.choice(admins)
        target = rng.choice(cast)
        occurred = now - timedelta(days=rng.randint(0, 89), hours=rng.randint(0, 23))
        entries.append(
            {
                "id": f"slack-audit-{index:04d}",
                "date_create": int(occurred.timestamp()),
                "action": action,
                "actor": {
                    "type": "user",
                    "user": {
                        "id": ids[actor.key],
                        "name": actor.display_name,
                        "email": actor.email,
                    },
                },
                "entity": {
                    "type": "user",
                    "user": {
                        "id": ids[target.key],
                        "name": target.display_name,
                        "email": target.email,
                    },
                },
                "context": {
                    "location": {
                        "type": "workspace",
                        "id": SLACK_TEAM_ID,
                        "name": "Acme Corp",
                        "domain": "acme",
                    }
                },
            }
        )
    # One old sign-in per dormant person, so Slack reports them stale rather
    # than falling back to the profile timestamp (which is not activity).
    for offset, persona in enumerate(p for p in cast if p.archetype is Archetype.DORMANT):
        occurred = now - timedelta(days=200 + offset)
        entries.append(
            {
                "id": f"slack-audit-dormant-{offset:02d}",
                "date_create": int(occurred.timestamp()),
                "action": "user_login",
                "actor": {
                    "type": "user",
                    "user": {"id": ids[persona.key], "name": persona.display_name, "email": persona.email},
                },
                "entity": {
                    "type": "user",
                    "user": {"id": ids[persona.key], "name": persona.display_name, "email": persona.email},
                },
                "context": {"location": {"type": "workspace", "id": SLACK_TEAM_ID, "name": "Acme Corp", "domain": "acme"}},
            }
        )
    entries.sort(key=lambda e: e["date_create"])
    return entries


# ---------------------------------------------------------------------------
# Okta
# ---------------------------------------------------------------------------

OKTA_ORG_URL = "https://acme.okta.com"


def okta_role_assignee(user_id: str) -> dict[str, Any]:
    """One ``/iam/assignees/users`` row, in the shape the bundled fixture uses."""
    return {
        "id": user_id,
        "orn": f"orn:okta:directory:00o1:users:{user_id}",
        "_links": {"roles": {"href": f"{OKTA_ORG_URL}/api/v1/users/{user_id}/roles"}},
    }


_OKTA_GROUPS = (
    "engineering",
    "security",
    "platform",
    "data",
    "sales",
    "support",
    "finance",
    "people",
    "contractors",
    "oncall",
    "admins",
    "everyone",
)

# (label, sign-on mode, scopes). The mix here is what populates the app
# inventory.
_OKTA_APPS: tuple[tuple[str, str, list[str]], ...] = (
    ("Slack", "OPENID_CONNECT", ["openid", "profile", "email", "channels:history"]),
    ("GitHub", "OPENID_CONNECT", ["openid", "repo", "okta.users.read"]),
    ("Google Workspace", "OPENID_CONNECT", ["openid", "email", "drive.readonly"]),
    ("Zoom", "OPENID_CONNECT", ["openid", "profile", "meeting:read"]),
    ("Notion", "OPENID_CONNECT", ["openid", "email", "read_content"]),
    ("Figma", "OPENID_CONNECT", ["openid", "file_read"]),
    ("Datadog", "OPENID_CONNECT", ["openid", "metrics_read"]),
    ("Snowflake", "OPENID_CONNECT", ["openid", "session:role:analyst"]),
    ("Salesforce", "SAML_2_0", []),
    ("Workday", "SAML_2_0", []),
    ("Internal HR", "SAML_2_0", []),
    ("Expensify", "SAML_2_0", []),
    ("Jira", "SAML_2_0", []),
    ("Confluence", "SAML_2_0", []),
    ("PagerDuty", "OPENID_CONNECT", ["openid", "incidents.read"]),
    ("Miro", "OPENID_CONNECT", ["openid", "boards:read"]),
    ("Airtable", "OPENID_CONNECT", ["openid", "data.records:read"]),
    ("Legacy HR Portal", "BOOKMARK", []),
    ("Intranet", "BOOKMARK", []),
    ("Status Page", "BOOKMARK", []),
)

_OKTA_ADMIN_ROLES = ("SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "READ_ONLY_ADMIN")


def _okta_id(prefix: str, index: int) -> str:
    """An Okta-shaped 20-character id, stable and unique for a given index.

    The padding width is derived from the prefix rather than truncating a
    fixed-width string: truncation drops the least-significant digits, which is
    exactly where uniqueness lives, so `0oa...0` and `0oa...1` collapse to the
    same id and every app after the first silently overwrites the previous one.
    """
    width = 20 - len(prefix)
    if index >= 10**width:
        raise ValueError(f"index {index} does not fit in {width} digits for prefix {prefix!r}")
    return f"{prefix}{index:0{width}d}"


def _write_okta_perimeter(target: Path) -> None:
    """Perimeter and automation surface.

    Shaped so the demo has findings that are not about people: a policy zone
    matching the whole internet, a legacy trusted origin on plain HTTP, an
    inline hook calling out over HTTP *during* authentication, a partner IdP
    that creates accounts on assertion, and a group rule turning a profile
    attribute into engineering-group membership.
    """
    _write(
        target / "network_zones.json",
        [
            {
                "id": "nzocorpoffice000001",
                "name": "Corporate office",
                "type": "IP",
                "usage": "POLICY",
                "status": "ACTIVE",
                "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}],
                "proxies": [],
            },
            {
                "id": "nzolegacyanywhere01",
                "name": "LegacyAnywhere",
                "type": "IP",
                "usage": "POLICY",
                "status": "ACTIVE",
                "gateways": [{"type": "CIDR", "value": "0.0.0.0/0"}],
                "proxies": [],
            },
        ],
    )
    _write(
        target / "trusted_origins.json",
        [
            {
                "id": "tosacmeapp000000001",
                "name": "Acme app",
                "origin": "https://app.acme.example.com",
                "status": "ACTIVE",
                "scopes": [{"type": "CORS"}, {"type": "REDIRECT"}],
            },
            {
                "id": "toslegacyportal0001",
                "name": "Legacy portal",
                "origin": "http://legacy.acme.example.com",
                "status": "ACTIVE",
                "scopes": [{"type": "REDIRECT"}],
            },
        ],
    )
    _write(
        target / "event_hooks.json",
        [
            {
                "id": "whosiemforward00001",
                "name": "SIEM forwarder",
                "status": "ACTIVE",
                "events": {
                    "type": "EVENT_TYPE",
                    "items": ["user.lifecycle.create", "user.account.privilege.grant"],
                },
                "channel": {
                    "type": "HTTP",
                    "version": "1.0.0",
                    "config": {"uri": "https://siem.example.test/okta/not-real"},
                },
            }
        ],
    )
    _write(
        target / "inline_hooks.json",
        [
            {
                "id": "calpasswordimport01",
                "name": "Legacy password import",
                "status": "ACTIVE",
                "type": "com.okta.user.credential.password.import",
                "channel": {
                    "type": "HTTP",
                    "version": "1.0.0",
                    "config": {"uri": "http://legacy-auth.example.test/verify"},
                },
            }
        ],
    )
    _write(
        target / "identity_providers.json",
        [
            {
                "id": "0oapartnersaml00001",
                "name": "Partner SAML",
                "type": "SAML2",
                "status": "ACTIVE",
                "policy": {"provisioning": {"action": "AUTO"}},
            }
        ],
    )
    _write(
        target / "group_rules.json",
        [
            {
                "id": "0prcontractorrule01",
                "name": "Contractors to Engineering",
                "status": "ACTIVE",
                "conditions": {
                    "expression": {
                        "value": 'user.userType=="Contractor"',
                        "type": "urn:okta:expression:1.0",
                    }
                },
                "actions": {"assignUserToGroups": {"groupIds": ["00gengineering000001"]}},
            }
        ],
    )


def _write_okta_policy_surface(target: Path) -> None:
    """Authentication and session policy surface.

    Deliberately imperfect, so the demo tenant has something to find: a global
    session policy whose default rule never expires and asks for no factor
    (Okta writes "unlimited" as 0 minutes), self-service registration left on,
    and WebAuthn present but inactive so only phishable factors are usable.
    """
    _write(
        target / "sign_on_policies.json",
        [
            {
                "id": "00pglobalsession0001",
                "type": "OKTA_SIGN_ON",
                "status": "ACTIVE",
                "name": "Default Policy",
                "system": True,
            }
        ],
    )
    _write(
        target / "policy_rules_00pglobalsession0001.json",
        [
            {
                "id": "0prdefaultsession001",
                "name": "Default Rule",
                "status": "ACTIVE",
                "priority": 1,
                "conditions": {"network": {"connection": "ANYWHERE"}},
                "actions": {
                    "signon": {
                        "access": "ALLOW",
                        "requireFactor": False,
                        "factorPromptMode": "NEVER",
                        "session": {
                            # 0 is Okta's encoding for "no limit".
                            "maxSessionLifetimeMinutes": 0,
                            "maxSessionIdleMinutes": 0,
                            "usePersistentCookie": True,
                        },
                    }
                },
            }
        ],
    )
    _write(
        target / "access_policies.json",
        [
            {
                "id": "00paccessadmin000001",
                "type": "ACCESS_POLICY",
                "status": "ACTIVE",
                "name": "Admin console policy",
                "system": False,
            }
        ],
    )
    _write(
        target / "policy_rules_00paccessadmin000001.json",
        [
            {
                "id": "0pradminaccess00001",
                "name": "Require MFA",
                "status": "ACTIVE",
                "priority": 1,
                "conditions": {"network": {"connection": "ANYWHERE"}},
                "actions": {
                    "signon": {
                        "access": "ALLOW",
                        "requireFactor": True,
                        "factorPromptMode": "ALWAYS",
                        "session": {
                            "maxSessionLifetimeMinutes": 10080,
                            "maxSessionIdleMinutes": 720,
                        },
                    }
                },
            }
        ],
    )
    _write(
        target / "profile_enrollment_policies.json",
        [
            {
                "id": "00pprofileenroll0001",
                "type": "PROFILE_ENROLLMENT",
                "status": "ACTIVE",
                "name": "Default Policy",
                "system": True,
            }
        ],
    )
    _write(
        target / "policy_rules_00pprofileenroll0001.json",
        [
            {
                "id": "0prprofileenroll001",
                "name": "Default Rule",
                "status": "ACTIVE",
                "priority": 1,
                "actions": {
                    "profileEnrollment": {
                        "access": "ALLOW",
                        "selfServiceRegistration": "ENABLED",
                    }
                },
            }
        ],
    )
    _write(
        target / "idp_discovery_policies.json",
        [
            {
                "id": "00pidpdiscovery00001",
                "type": "IDP_DISCOVERY",
                "status": "ACTIVE",
                "name": "Idp Discovery Policy",
                "system": True,
            }
        ],
    )
    _write(
        target / "policy_rules_00pidpdiscovery00001.json",
        [
            {
                "id": "0pridpdiscovery0001",
                "name": "Default Rule",
                "status": "ACTIVE",
                "priority": 1,
                "actions": {"idp": {"providers": [{"type": "OKTA"}]}},
            }
        ],
    )
    _write(
        target / "authenticators.json",
        [
            {
                "id": "autpassword00000001",
                "key": "okta_password",
                "name": "Password",
                "type": "password",
                "status": "ACTIVE",
            },
            {"id": "autoktaverify000001", "key": "okta_verify", "name": "Okta Verify", "type": "app", "status": "ACTIVE"},
            # Present but never turned on -- the org has MFA, and none of it
            # resists an attacker-in-the-middle proxy.
            {
                "id": "autwebauthn00000001",
                "key": "webauthn",
                "name": "Security Key or Biometric",
                "type": "security_key",
                "status": "INACTIVE",
            },
        ],
    )
    _write_okta_perimeter(target)
    _write(
        target / "device_assurances.json",
        [
            # Defined but not referenced by any active rule above -- device
            # assurance configured and never enforced is the common shape.
            {
                "id": "daemacosbaseline0001",
                "name": "macOS baseline",
                "platform": "MACOS",
                "diskEncryptionType": {"include": ["FULL"]},
                "screenLockType": {"include": ["BIOMETRIC", "PASSCODE"]},
                "secureHardwarePresent": True,
            },
            {
                # Screen lock only. The macOS policy requires disk encryption
                # and this one never caught up -- the usual mixed-fleet drift.
                "id": "dawindowsbaseline001",
                "name": "Windows baseline",
                "platform": "WINDOWS",
                "screenLockType": {"include": ["PASSCODE"]},
                "secureHardwarePresent": False,
            },
        ],
    )


def generate_okta(
    target: Path,
    personas: list[Persona],
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """Write a full Okta org fixture tree for the given roster."""
    cast = roster_for(personas, "okta")
    ids = {p.key: _okta_id("00u", index) for index, p in enumerate(cast)}
    _assert_unique("okta user", list(ids.values()))

    _write(
        target / "org.json",
        {
            "id": "00oacmeorg000000001",
            "subdomain": "acme",
            "companyName": "Acme Corp",
            "status": "ACTIVE",
            "created": "2020-01-01T00:00:00.000Z",
        },
    )
    _write(target / "empty_list.json", [])
    _write(target / "threat_insight.json", {"action": "none", "excludeUsers": []})
    _write(
        target / "password_policies.json",
        [
            {
                "id": "00ppassword000000001",
                "type": "PASSWORD",
                "status": "ACTIVE",
                "name": "Default Policy",
                "settings": {
                    "password": {
                        "complexity": {
                            "minLength": 8,
                            "minLowerCase": 1,
                            "minUpperCase": 1,
                            "minNumber": 1,
                            "minSymbol": 0,
                            "excludeUsername": False,
                        }
                    }
                },
            }
        ],
    )
    _write(
        target / "mfa_enroll_policies.json",
        [
            {
                "id": "00pmfaenroll00000001",
                "type": "MFA_ENROLL",
                "status": "ACTIVE",
                "name": "Default MFA Enrollment",
                "settings": {
                    "factors": {
                        "okta_otp": {"enroll": {"self": "OPTIONAL"}},
                        "okta_sms": {"enroll": {"self": "OPTIONAL"}},
                    }
                },
            }
        ],
    )
    _write_okta_policy_surface(target)

    # -- users -------------------------------------------------------------
    users: list[dict[str, Any]] = []
    for persona in cast:
        user_id = ids[persona.key]
        if persona.archetype is Archetype.DORMANT:
            last_login = now - timedelta(days=rng.randint(120, 400))
        elif persona.is_disabled:
            last_login = now - timedelta(days=rng.randint(200, 500))
        elif persona.is_external:
            # A contractor whose engagement ended without anyone disabling the
            # account: the cross-app dormant-contractor beat.
            last_login = now - timedelta(days=rng.randint(60, 120))
        else:
            last_login = now - timedelta(days=rng.randint(0, 20))

        factors: list[dict[str, Any]] = []
        if persona.has_mfa:
            factors.append(
                {
                    "id": f"mfa-{user_id[-6:]}",
                    "factorType": rng.choice(["token:software:totp", "push", "sms"]),
                    "provider": "OKTA",
                    "status": "ACTIVE",
                }
            )
        users.append(
            {
                "id": user_id,
                "status": "DEPROVISIONED" if persona.is_disabled else "ACTIVE",
                "created": _iso(now - timedelta(days=rng.randint(60, 1500))).replace("Z", ".000Z"),
                "lastLogin": _iso(last_login).replace("Z", ".000Z"),
                # Offboarding ran six weeks ago; the surviving local accounts
                # elsewhere are what the departed-account policies report.
                **({"statusChanged": _iso(now - timedelta(days=45)).replace("Z", ".000Z")} if persona.is_disabled else {}),
                "profile": {
                    "firstName": persona.first_name,
                    "lastName": persona.last_name,
                    "email": persona.email,
                    "login": persona.email,
                    "department": persona.department,
                    "title": persona.title,
                    **({"userType": "Contractor", "isExternal": True} if persona.is_external else {}),
                },
                "factors": factors,
            }
        )
    _write(target / "users.json", users)

    # Admin role assignments. The deprovisioned admin keeps SUPER_ADMIN -- that
    # orphaned-privilege pairing is the point of the archetype.
    role_holders: list[str] = []
    for persona in cast:
        user_id = ids[persona.key]
        if not persona.is_admin:
            continue
        role_holders.append(user_id)
        role_type = "SUPER_ADMIN" if persona.archetype is Archetype.DEPROVISIONED_ADMIN else rng.choice(_OKTA_ADMIN_ROLES)
        _write(
            target / f"user_roles_{user_id}.json",
            [
                {
                    "id": f"rol-{user_id[-8:]}",
                    "type": role_type,
                    "status": "ACTIVE",
                    "assignmentType": "USER",
                }
            ],
        )
        if persona.has_mfa:
            _write(
                target / f"user_factors_{user_id}.json",
                [
                    {
                        "id": f"mfa-{user_id[-6:]}",
                        "factorType": "token:software:totp",
                        "provider": "OKTA",
                        "status": "ACTIVE",
                    }
                ],
            )

    # The collector only asks /users/{id}/roles about the users this endpoint
    # lists. Without the generated file the bundled one is copied in, whose
    # ids are not in this directory, and every role above goes unread.
    _write(target / "role_assignees.json", {"value": [okta_role_assignee(u) for u in role_holders]})

    # -- groups ------------------------------------------------------------
    groups: list[dict[str, Any]] = []
    for index, name in enumerate(_OKTA_GROUPS):
        group_id = _okta_id("00g", index)
        groups.append(
            {
                "id": group_id,
                "type": "OKTA_GROUP",
                "profile": {"name": name, "description": name.title()},
            }
        )
        size = len(cast) if name == "everyone" else rng.randint(4, max(5, len(cast) // 3))
        members = cast if name == "everyone" else rng.sample(cast, min(size, len(cast)))
        _write(
            target / f"group_users_{group_id}.json",
            [{"id": ids[p.key], "status": "ACTIVE", "profile": {"email": p.email}} for p in members],
        )
        # A couple of groups carry an admin role, which is what produces the
        # `assigned_role / inherited_group` edge Explore filters on.
        if name in {"security", "admins"}:
            _write(
                target / f"group_roles_{group_id}.json",
                [
                    {
                        "id": f"rol-{group_id[-8:]}",
                        "type": "GROUP_ADMIN" if name == "security" else "ORG_ADMIN",
                        "status": "ACTIVE",
                        "assignmentType": "GROUP",
                    }
                ],
            )
    _assert_unique("okta group", [g["id"] for g in groups])
    _write(target / "groups.json", groups)

    # -- applications ------------------------------------------------------
    apps: list[dict[str, Any]] = []
    for index, (label, sign_on, scopes) in enumerate(_OKTA_APPS):
        app_id = _okta_id("0oa", index)
        app: dict[str, Any] = {
            "id": app_id,
            "name": label.lower().replace(" ", "_"),
            "label": label,
            "status": "ACTIVE",
            "signOnMode": sign_on,
            "created": "2023-01-01T00:00:00.000Z",
            "lastUpdated": "2024-06-01T00:00:00.000Z",
        }
        if sign_on == "OPENID_CONNECT":
            app["credentials"] = {"oauthClient": {"client_id": f"{app['name']}.client"}}
            app["settings"] = {"oauthClient": {"scopes": scopes, "grant_types": ["authorization_code"]}}
        apps.append(app)

        assignees = rng.sample(cast, rng.randint(2, max(3, len(cast) // 4)))
        _write(
            target / f"app_users_{app_id}.json",
            [
                {
                    "id": ids[p.key],
                    "status": "ACTIVE",
                    # GROUP-scoped assignments are skipped for the identity edge
                    # on purpose, so group-granted access stays a two-hop path.
                    "scope": rng.choice(["USER", "USER", "GROUP"]),
                    "created": "2023-02-02T00:00:00.000Z",
                    "lastUpdated": None,
                }
                for p in assignees
            ],
        )
        if rng.random() < 0.5:
            group = rng.choice(groups)
            _write(
                target / f"app_groups_{app_id}.json",
                [{"id": group["id"], "lastUpdated": "2024-02-01T00:00:00.000Z", "priority": 0}],
            )
    _assert_unique("okta app", [a["id"] for a in apps])
    _write(target / "apps.json", apps)

    # -- API tokens --------------------------------------------------------
    token_owners = rng.sample(cast, min(4, len(cast)))
    _write(
        target / "api_tokens.json",
        [
            {
                "id": _okta_id("00t", index),
                "name": name,
                "userId": ids[owner.key],
                "created": _iso(now - timedelta(days=rng.randint(100, 900))).replace("Z", ".000Z"),
                "lastUpdated": _iso(now - timedelta(days=rng.randint(0, 90))).replace("Z", ".000Z"),
            }
            for index, (name, owner) in enumerate(
                zip(
                    ("Legacy automation token", "Terraform provider", "SCIM bridge", "Backup job"),
                    token_owners,
                    strict=False,
                )
            )
        ],
    )

    _write(target / "system_log.json", _okta_system_log(cast, ids, rng=rng, now=now))


def _okta_system_log(
    cast: list[Persona],
    ids: dict[str, str],
    *,
    rng: random.Random,
    now: datetime,
    count: int = 55,
) -> list[dict[str, Any]]:
    admins = [p for p in cast if p.is_admin] or cast[:1]
    events = (
        ("user.account.privilege.grant", "Grant user privilege", "SUCCESS"),
        ("user.mfa.factor.deactivate", "Deactivate factor", "SUCCESS"),
        ("security.threat.detected", "Threat detected", "FAILURE"),
        ("api.token.create", "Create API token", "SUCCESS"),
        ("user.account.privilege.revoke", "Revoke user privilege", "SUCCESS"),
        ("user.session.start", "User login", "SUCCESS"),  # noise, dropped
    )
    entries: list[dict[str, Any]] = []
    for index in range(count):
        event_type, message, outcome = events[index % len(events)]
        actor = rng.choice(admins)
        target = rng.choice(cast)
        occurred = now - timedelta(days=rng.randint(0, 89), hours=rng.randint(0, 23))
        entry = {
            "uuid": f"okta-log-{index:04d}",
            "published": _iso(occurred).replace("Z", ".000Z"),
            "eventType": event_type,
            "severity": "WARN" if outcome == "FAILURE" else "INFO",
            "displayMessage": message,
            "actor": {
                "id": ids[actor.key],
                "type": "User",
                "alternateId": actor.email,
                "displayName": actor.display_name,
            },
            "outcome": {"result": outcome},
            "target": [
                {
                    "id": ids[target.key],
                    "type": "User",
                    "alternateId": target.email,
                    "displayName": target.display_name,
                    **(
                        {"detailEntry": {"privilegeGranted": rng.choice(_OKTA_ADMIN_ROLES)}}
                        if event_type == "user.account.privilege.grant"
                        else {}
                    ),
                }
            ],
        }
        entries.append(entry)
    entries.sort(key=lambda e: str(e["published"]))
    return entries


def generate_fixtures(
    root: Path,
    *,
    seed: int = DEFAULT_SEED,
    roster_size: int = 100,
    now: datetime | None = None,
) -> dict[str, Path]:
    """Write every tenant's fixture tree under `root`.

    Returns `{connector_name: fixtures_dir}`.
    """
    clock = now or datetime.now(UTC)
    personas = build_roster(size=roster_size, seed=seed)

    github_dir = root / "github"
    generate_github(github_dir, personas, rng=random.Random(seed + 1), now=clock)

    slack_dir = root / "slack"
    generate_slack(slack_dir, personas, rng=random.Random(seed + 2), now=clock)

    okta_dir = root / "okta"
    generate_okta(okta_dir, personas, rng=random.Random(seed + 3), now=clock)

    gws_dir = root / "google_workspace"
    generate_google_workspace(gws_dir, personas, rng=random.Random(seed + 4), now=clock)

    _fill_from_bundled(github_dir, "kestrel_connector_github")
    _fill_from_bundled(slack_dir, "kestrel_connector_slack")
    _fill_from_bundled(okta_dir, "kestrel_connector_okta")
    _fill_from_bundled(gws_dir, "kestrel_connector_google_workspace")

    return {"github": github_dir, "slack": slack_dir, "okta": okta_dir, "google_workspace": gws_dir}


def _fill_from_bundled(target: Path, connector_package: str) -> None:
    """Copy every bundled fixture file the generator did not produce.

    Tenant-level posture documents (Actions permissions, sign-on and session
    policies, authenticators, network zones, app activities) are the same for
    every demo tenant, so they are not generated; the connector's fixture
    transport still maps them, and a mapped file that is missing is an error.
    Copying the bundled versions keeps the generated tree complete without
    teaching the generator about every connector's static documents.
    """
    import importlib
    import shutil

    module = importlib.import_module(f"{connector_package}.fixture_transport")
    bundled = Path(module.FIXTURES_DIR)
    for source in sorted(bundled.glob("*.json")):
        destination = target / source.name
        if not destination.exists():
            shutil.copyfile(source, destination)


# ---------------------------------------------------------------------------
# Google Workspace
# ---------------------------------------------------------------------------

GWS_DOMAIN = "acme.example.com"
GWS_ALIAS_DOMAIN = "acme-corp.example.com"
GWS_CUSTOMER_ID = "C0demoacme"

# Organizational units. Contractors sit in their own OU with inheritance
# blocked, which is how a real tenant carves out a weaker policy -- and why
# "who is in /Contractors" is worth asking.
_GWS_ORG_UNITS: tuple[tuple[str, str, str | None, bool], ...] = (
    ("id:ou-root", "/", None, False),
    ("id:ou-eng", "/Engineering", "id:ou-root", False),
    ("id:ou-sales", "/Sales", "id:ou-root", False),
    ("id:ou-contractors", "/Contractors", "id:ou-root", True),
)

_GWS_ROLES: tuple[tuple[str, str, str, bool, list[str]], ...] = (
    ("300000000000001", "_SEED_ADMIN_ROLE", "Super Admin", True, ["SUPER_ADMIN"]),
    ("300000000000002", "_HELP_DESK_ADMIN_ROLE", "Help Desk Admin", False, ["USERS_RESET_PASSWORD", "USERS_RETRIEVE"]),
    ("300000000000003", "_GROUPS_ADMIN_ROLE", "Groups Admin", False, ["GROUPS_ALL", "GROUPS_UPDATE"]),
    ("300000000000004", "Reporting Reader", "Custom read-only reporting role", False, ["REPORTS_RETRIEVE"]),
)

_GWS_SHARED_DRIVES: tuple[tuple[str, str, bool], ...] = (
    ("500000000000001", "Finance", False),
    ("500000000000002", "Engineering", False),
    # Restrictions off: the drive anyone with the link can read.
    ("500000000000003", "Board Materials", True),
)

# Third-party apps people consent to. The over-scoped ones are what the
# risky-OAuth policies fire on.
_GWS_OAUTH_APPS: tuple[tuple[str, str, list[str], bool], ...] = (
    ("1000-slack.apps.googleusercontent.com", "Slack", ["openid", "https://www.googleapis.com/auth/userinfo.email"], False),
    (
        "2000-mailmerge.apps.googleusercontent.com",
        "MailMerge Pro",
        ["https://mail.google.com/", "https://www.googleapis.com/auth/contacts"],
        True,
    ),
    (
        "3000-drivesync.apps.googleusercontent.com",
        "Drive Explorer Sync",
        ["https://www.googleapis.com/auth/drive"],
        True,
    ),
    (
        "4000-calendarpal.apps.googleusercontent.com",
        "Calendar Pal",
        ["https://www.googleapis.com/auth/calendar.readonly"],
        False,
    ),
)


def _gws_user_id(index: int) -> str:
    return f"1{index:020d}"


def _gws_org_unit_for(persona: Persona) -> str:
    if persona.is_external:
        return "/Contractors"
    if persona.department in {"Engineering", "Platform", "Data"}:
        return "/Engineering"
    if persona.department in {"Sales", "Support"}:
        return "/Sales"
    return "/"


def generate_google_workspace(
    target: Path,
    personas: list[Persona],
    *,
    rng: random.Random,
    now: datetime,
    group_count: int = 9,
) -> None:
    """Write a Google Workspace fixture tree for the roster.

    Shapes the demo needs from Workspace specifically: super admins with and
    without 2-Step Verification, a group that accepts external members, an
    external member actually sitting in it, shared drives including one anyone
    with the link can read, and third-party OAuth grants with Gmail and Drive
    scopes.
    """
    cast = roster_for(personas, "google_workspace")
    ids = {persona.key: _gws_user_id(index + 1) for index, persona in enumerate(cast)}

    _write(
        target / "domain.json",
        {
            "kind": "admin#directory#domains",
            "domainName": GWS_DOMAIN,
            "isPrimary": True,
            "verified": True,
        },
    )
    _write(
        target / "domains.json",
        [
            {
                "kind": "admin#directory#domain",
                "domainName": GWS_DOMAIN,
                "isPrimary": True,
                "verified": True,
                "domainAliases": [{"domainAliasName": GWS_ALIAS_DOMAIN, "verified": True}],
            },
            {
                "kind": "admin#directory#domain",
                "domainName": "acme-labs.example.com",
                "isPrimary": False,
                "verified": False,
                "domainAliases": [],
            },
        ],
    )
    _write(
        target / "org_units.json",
        [
            {
                "kind": "admin#directory#orgUnit",
                "orgUnitId": unit_id,
                "orgUnitPath": path,
                "name": path.rsplit("/", 1)[-1] or GWS_DOMAIN,
                "parentOrgUnitId": parent,
                "blockInheritance": blocked,
            }
            for unit_id, path, parent, blocked in _GWS_ORG_UNITS
        ],
    )

    users: list[dict[str, Any]] = []
    for persona in cast:
        if persona.archetype is Archetype.DORMANT:
            last_login = now - timedelta(days=rng.randint(200, 400))
        elif persona.is_external:
            last_login = now - timedelta(days=rng.randint(60, 120))
        else:
            last_login = now - timedelta(days=rng.randint(0, 20))
        users.append(
            {
                "kind": "admin#directory#user",
                "id": ids[persona.key],
                "primaryEmail": persona.email,
                "name": {
                    "givenName": persona.first_name,
                    "familyName": persona.last_name,
                    "fullName": persona.display_name,
                },
                "isAdmin": persona.is_admin and not persona.is_disabled,
                "isDelegatedAdmin": False,
                "suspended": persona.is_disabled,
                "archived": False,
                "isEnrolledIn2Sv": persona.has_mfa,
                # Enforcement tracks the org unit in most tenants: staff are
                # enforced, externals and contractors are the gap.
                "isEnforcedIn2Sv": not persona.is_external,
                "orgUnitPath": _gws_org_unit_for(persona),
                "lastLoginTime": _iso(last_login),
                "creationTime": _iso(now - timedelta(days=rng.randint(200, 1200))),
            }
        )
    _assert_unique("google workspace user", [u["id"] for u in users])
    _write(target / "users.json", users)

    # -- groups -------------------------------------------------------------
    group_names = [
        "Engineering",
        "Security",
        "Sales",
        "All Staff",
        "Finance",
        "Leadership",
        "Support",
        "Vendors",
        "Announcements",
    ]
    groups: list[dict[str, Any]] = []
    for index, name in enumerate(group_names[:group_count]):
        groups.append(
            {
                "kind": "admin#directory#group",
                "id": f"2{index:020d}",
                "email": f"{name.lower().replace(' ', '-')}@{GWS_DOMAIN}",
                "name": name,
                "description": f"{name} distribution group",
            }
        )
    _write(target / "groups.json", groups)

    external_pool = [p for p in personas if p.is_external]
    for index, group in enumerate(groups):
        members = list(rng.sample(cast, min(len(cast), rng.randint(4, 12))))
        rows = [
            {
                "kind": "admin#directory#member",
                "id": ids[p.key],
                "email": p.email,
                "role": "MANAGER" if p.is_admin else "MEMBER",
                "type": "USER",
                "status": "ACTIVE",
            }
            for p in members
        ]
        # "Vendors" is the group that legitimately carries outsiders; one other
        # group carries one by accident, which is the finding.
        if group["name"] in {"Vendors", "Engineering"} and external_pool:
            outsider = external_pool[index % len(external_pool)]
            rows.append(
                {
                    "kind": "admin#directory#member",
                    "id": f"9{index:020d}",
                    "email": outsider.email,
                    "role": "MEMBER",
                    "type": "USER",
                    "status": "ACTIVE",
                }
            )
        _write(target / f"group_members_{group['id']}.json", rows)
        _write(
            target / f"group_settings_{group['email']}.json",
            {
                "kind": "groupsSettings#groups",
                "email": group["email"],
                "allowExternalMembers": "true" if group["name"] in {"Vendors", "Engineering"} else "false",
                # "Announcements" is the old open list nobody revisited: anyone
                # with a Google account can still join it.
                "whoCanJoin": (
                    "ANYONE_CAN_JOIN"
                    if group["name"] == "Announcements"
                    else "ALL_IN_DOMAIN_CAN_JOIN"
                    if group["name"] == "All Staff"
                    else "INVITED_CAN_JOIN"
                ),
                "whoCanPostMessage": "ANYONE_CAN_POST" if group["name"] == "Support" else "ALL_MEMBERS_CAN_POST",
                "whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW",
            },
        )

    # -- admin roles and assignments ---------------------------------------
    _write(
        target / "roles.json",
        [
            {
                "kind": "admin#directory#role",
                "roleId": role_id,
                "roleName": role_name,
                "roleDescription": label,
                "isSuperAdminRole": is_super,
                "isSystemRole": not role_name[0].isupper() or role_name.startswith("_"),
                "rolePrivileges": [{"privilegeName": p, "serviceId": "00haapch16h1ysv"} for p in privileges],
            }
            for role_id, role_name, label, is_super, privileges in _GWS_ROLES
        ],
    )
    assignments: list[dict[str, Any]] = []
    admins = [p for p in cast if p.is_admin]
    for index, persona in enumerate(admins):
        # Grace-style admins keep Super Admin; the rest spread across the
        # lesser roles so the pack has both shapes.
        role_id = "300000000000001" if index % 3 == 0 else _GWS_ROLES[1 + (index % 3)][0]
        assignments.append(
            {
                "kind": "admin#directory#roleAssignment",
                "roleAssignmentId": f"4{index:020d}",
                "roleId": role_id,
                "assignedTo": ids[persona.key],
                "scopeType": "CUSTOMER",
            }
        )
    _write(target / "role_assignments.json", assignments)

    # -- shared drives ------------------------------------------------------
    _write(
        target / "shared_drives.json",
        [
            {"kind": "drive#drive", "id": drive_id, "name": name, "createdTime": _iso(now - timedelta(days=400))}
            for drive_id, name, _open_link in _GWS_SHARED_DRIVES
        ],
    )
    for drive_id, _name, open_link in _GWS_SHARED_DRIVES:
        members = rng.sample(cast, min(len(cast), rng.randint(3, 8)))
        permissions: list[dict[str, Any]] = [
            {
                "kind": "drive#permission",
                "id": f"perm-{drive_id}-{position}",
                "type": "user",
                "emailAddress": person.email,
                "role": "organizer" if position == 0 else rng.choice(["writer", "reader", "commenter"]),
            }
            for position, person in enumerate(members)
        ]
        if open_link:
            permissions.append(
                {
                    "kind": "drive#permission",
                    "id": f"perm-{drive_id}-anyone",
                    "type": "anyone",
                    "role": "reader",
                    "allowFileDiscovery": False,
                }
            )
        _write(target / f"drive_permissions_{drive_id}.json", permissions)

    # -- per-user OAuth tokens ---------------------------------------------
    for persona in cast:
        if persona.is_disabled:
            continue
        granted = [_GWS_OAUTH_APPS[0]]
        if rng.random() < 0.35:
            granted.append(rng.choice(_GWS_OAUTH_APPS[1:]))
        _write(
            target / f"user_tokens_{ids[persona.key]}.json",
            [
                {
                    "kind": "admin#directory#token",
                    "clientId": client_id,
                    "displayText": label,
                    "anonymous": risky,
                    "nativeApp": False,
                    "userKey": ids[persona.key],
                    "scopes": scopes,
                }
                for client_id, label, scopes, risky in granted
            ],
        )
    _write(target / "user_tokens_empty.json", [])

    # -- reports ------------------------------------------------------------
    login_events = []
    for index, persona in enumerate(rng.sample(cast, min(len(cast), 8))):
        name = ["login_failure", "suspicious_login", "login_success", "2sv_disable"][index % 4]
        login_events.append(
            {
                "kind": "admin#reports#activity",
                "id": {
                    "time": _iso(now - timedelta(days=index, hours=3)),
                    "uniqueQualifier": str(2000 + index),
                    "applicationName": "login",
                    "customerId": GWS_CUSTOMER_ID,
                },
                "actor": {"email": persona.email, "profileId": ids[persona.key]},
                "ipAddress": f"203.0.113.{10 + index}",
                "events": [
                    {"type": "login", "name": name, "parameters": [{"name": "login_type", "value": "google_password"}]}
                ],
            }
        )
    _write(target / "login_activities.json", login_events)
