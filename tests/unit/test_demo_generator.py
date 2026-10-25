# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- the demo fixture generator is deterministic and internally consistent.

`demo up` builds its tenants from this generator rather than the bundled
fixtures, so a bug here is a broken demo on every machine at once. The
properties worth pinning are the ones that failed in development: id
uniqueness (a truncated id generator silently collapsed every app into one),
determinism (two machines must produce the same demo), and cross-connector
email joins (the whole point of the shared roster).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from kestrel.demo.generate import generate_fixtures
from kestrel.demo.personas import Archetype, build_roster, roster_for

NOW = datetime(2026, 8, 28, tzinfo=UTC)


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return generate_fixtures(tmp_path_factory.mktemp("fixtures"), now=NOW)


def _load(directory: Path, name: str):
    return json.loads((directory / name).read_text())


# -- roster ---------------------------------------------------------------


def test_roster_is_deterministic() -> None:
    assert [p.email for p in build_roster()] == [p.email for p in build_roster()]


def test_roster_emails_are_unique() -> None:
    # Email is the only cross-connector join key; a duplicate silently collapses
    # two people into one identity in the graph.
    roster = build_roster()
    assert len({p.email for p in roster}) == len(roster)


def test_roster_covers_every_archetype() -> None:
    seen = {p.archetype for p in build_roster()}
    assert seen == set(Archetype)


def test_every_tenant_has_a_meaningful_population() -> None:
    roster = build_roster()
    for tenant in ("github", "slack", "okta"):
        assert len(roster_for(roster, tenant)) >= 40


def test_people_span_tenants_rather_than_appearing_in_all_of_them() -> None:
    # An org where everyone is in every app has no cross-app story to tell.
    roster = build_roster()
    spans = Counter(len(p.tenants) for p in roster)
    assert spans[3] > 10
    assert spans[1] + spans[2] > 10


# -- generation -----------------------------------------------------------


def test_generation_is_byte_identical_across_runs(tmp_path: Path) -> None:
    first = generate_fixtures(tmp_path / "a", now=NOW)
    second = generate_fixtures(tmp_path / "b", now=NOW)
    for connector, directory in first.items():
        for path in sorted(directory.glob("*.json")):
            other = second[connector] / path.name
            assert path.read_text() == other.read_text(), f"{connector}/{path.name} differs"


def test_every_demo_tenant_is_generated(generated: dict[str, Path]) -> None:
    assert set(generated) == {"github", "slack", "okta", "google_workspace"}


def test_google_workspace_ids_are_unique_and_the_roster_overlaps(generated: dict[str, Path]) -> None:
    root = generated["google_workspace"]
    users = _load(root, "users.json")
    ids = [u["id"] for u in users]
    emails = [u["primaryEmail"] for u in users]
    assert len(set(ids)) == len(ids)
    assert len(set(emails)) == len(emails)
    # The cross-app story needs people who exist in Workspace *and* elsewhere.
    okta_emails = {u["profile"]["email"] for u in _load(generated["okta"], "users.json")}
    assert len(set(emails) & okta_emails) >= 10


def test_google_workspace_carries_the_shapes_the_pack_needs(generated: dict[str, Path]) -> None:
    """Each of these is a policy with no subject if the generator omits it."""
    root = generated["google_workspace"]
    users = _load(root, "users.json")
    assert any(u["isAdmin"] and not u["isEnrolledIn2Sv"] for u in users), "no super admin without 2SV"
    assert any(u["suspended"] for u in users), "no suspended account"
    assert {u["orgUnitPath"] for u in users} > {"/"}, "every user is in the root OU"

    settings = [json.loads(path.read_text()) for path in root.glob("group_settings_*.json")]
    assert any(s["allowExternalMembers"] == "true" for s in settings), "no group accepting external members"

    permissions = [row for path in root.glob("drive_permissions_*.json") for row in json.loads(path.read_text())]
    assert any(p["type"] == "anyone" for p in permissions), "no link-shared drive"

    tokens = [row for path in root.glob("user_tokens_*.json") for row in json.loads(path.read_text())]
    assert any("mail.google.com" in scope for t in tokens for scope in t["scopes"]), "no app with a Gmail scope"


def test_github_ids_are_unique(generated: dict[str, Path]) -> None:
    root = generated["github"]
    members = _load(root, "members_admin.json") + _load(root, "members_member.json")
    ids = [m["id"] for m in members] + [m["id"] for m in _load(root, "outside_collaborators.json")]
    assert len(set(ids)) == len(ids)
    repos = _load(root, "repos.json")
    assert len({r["id"] for r in repos}) == len(repos)
    assert len({r["name"] for r in repos}) == len(repos)


def test_okta_ids_are_unique_and_correctly_shaped(generated: dict[str, Path]) -> None:
    # Regression: the id builder padded then truncated to 20 characters, which
    # dropped the least-significant digits -- every app collapsed onto one id.
    root = generated["okta"]
    for filename, prefix in (("users.json", "00u"), ("groups.json", "00g"), ("apps.json", "0oa")):
        rows = _load(root, filename)
        ids = [r["id"] for r in rows]
        assert len(set(ids)) == len(ids), f"{filename} has duplicate ids"
        assert all(len(i) == 20 and i.startswith(prefix) for i in ids)


def test_slack_ids_are_unique(generated: dict[str, Path]) -> None:
    root = generated["slack"]
    users = _load(root, "users.json")
    assert len({u["id"] for u in users}) == len(users)
    apps = _load(root, "approved_apps.json")
    assert len({a["app_id"] for a in apps}) == len(apps)


def test_every_team_and_repo_has_its_per_entity_file(generated: dict[str, Path]) -> None:
    # An unreferenced per-entity file resolves to an empty response rather than
    # failing, so a missing one is invisible without this check.
    root = generated["github"]
    for team in _load(root, "teams.json"):
        assert (root / f"team_members_{team['slug']}.json").exists()
        assert (root / f"team_repos_{team['slug']}.json").exists()
    for repo in _load(root, "repos.json"):
        assert (root / f"repo_collaborators_{repo['name']}.json").exists()


def test_okta_per_entity_files_exist_for_groups_and_apps(generated: dict[str, Path]) -> None:
    root = generated["okta"]
    for group in _load(root, "groups.json"):
        assert (root / f"group_users_{group['id']}.json").exists()
    for app in _load(root, "apps.json"):
        assert (root / f"app_users_{app['id']}.json").exists()


def test_the_same_person_carries_one_email_across_tenants(generated: dict[str, Path]) -> None:
    github = {
        m["email"]
        for m in _load(generated["github"], "members_admin.json") + _load(generated["github"], "members_member.json")
    }
    slack = {u["profile"]["email"] for u in _load(generated["slack"], "users.json")}
    okta = {u["profile"]["email"] for u in _load(generated["okta"], "users.json")}
    # The anchors are in all three by construction.
    for email in ("grace@acme.example.com", "ada@acme.example.com", "alan@acme.example.com"):
        assert email in github
        assert email in slack
        assert email in okta
    assert len(github & slack & okta) >= 20


def test_the_dataset_contains_the_archetypes_policies_fire_on(
    generated: dict[str, Path],
) -> None:
    root = generated["github"]
    assert _load(root, "members_2fa_disabled.json"), "no admins without MFA to find"
    assert _load(root, "outside_collaborators.json"), "no external collaborators to find"
    org = _load(root, "org.json")
    assert org["two_factor_requirement_enabled"] is False

    okta_users = _load(generated["okta"], "users.json")
    assert any(u["status"] == "DEPROVISIONED" for u in okta_users)
    assert any(not u["factors"] for u in okta_users)


def test_audit_history_spans_the_full_window(generated: dict[str, Path]) -> None:
    entries = _load(generated["github"], "audit_log.json")
    assert len(entries) >= 40
    stamps = sorted(e["created_at"] for e in entries)
    assert stamps[0] < stamps[-1], "audit entries must not share one timestamp"
    assert len({e["_document_id"] for e in entries}) == len(entries)
