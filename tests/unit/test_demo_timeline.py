# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- generated fixtures collect cleanly, and the drift timeline fires.

Two failure modes this guards, both hit in development:

* A generated fixture tree the connector cannot read. The mapping is derived
  from fixture *content*, so a shape change silently produces an unmapped
  signature and `FixtureTransport` raises mid-collection.
* A timeline step that quietly does nothing. Steps resolve people by email and
  return `[]` when they cannot find them, so a step written against the wrong
  file just... never happens, and the demo is missing a beat with no error.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from kestrel.connectors.sdk.runner import run_collection
from kestrel.demo.generate import (
    GITHUB_ORG_LOGIN,
    GWS_DOMAIN,
    OKTA_ORG_URL,
    SLACK_TEAM_ID,
    generate_fixtures,
)
from kestrel.demo.timeline import TIMELINE, apply_steps, steps_for, tenants_at

NOW = datetime(2026, 8, 28, tzinfo=UTC)


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return generate_fixtures(tmp_path_factory.mktemp("fixtures"), now=NOW)


def _collect(connector_name: str, fixtures_dir: Path):
    if connector_name == "github":
        from kestrel_connector_github.connector import GitHubConnector
        from kestrel_connector_github.fixture_transport import build_fixture_transport

        return run_collection(
            GitHubConnector(),
            config={"org_login": GITHUB_ORG_LOGIN},
            transport_override=build_fixture_transport(GITHUB_ORG_LOGIN, fixtures_dir=fixtures_dir),
        )
    if connector_name == "slack":
        from kestrel_connector_slack.connector import SlackConnector
        from kestrel_connector_slack.fixture_transport import build_fixture_transport

        return run_collection(
            SlackConnector(),
            config={"team_id": SLACK_TEAM_ID},
            transport_override=build_fixture_transport(SLACK_TEAM_ID, fixtures_dir=fixtures_dir),
        )
    if connector_name == "google_workspace":
        from kestrel_connector_google_workspace.connector import GoogleWorkspaceConnector
        from kestrel_connector_google_workspace.fixture_transport import build_fixture_transport

        return run_collection(
            GoogleWorkspaceConnector(),
            config={"domain": GWS_DOMAIN},
            transport_override=build_fixture_transport(GWS_DOMAIN, fixtures_dir=fixtures_dir),
        )
    from kestrel_connector_okta.connector import OktaConnector
    from kestrel_connector_okta.fixture_transport import build_fixture_transport

    return run_collection(
        OktaConnector(),
        config={"org_url": OKTA_ORG_URL},
        transport_override=build_fixture_transport(OKTA_ORG_URL, fixtures_dir=fixtures_dir),
    )


@pytest.mark.parametrize("connector_name", ["github", "slack", "okta", "google_workspace"])
def test_generated_fixtures_collect_without_an_unmapped_request(connector_name: str, generated: dict[str, Path]) -> None:
    result = _collect(connector_name, generated[connector_name])
    assert result.normalized_objects
    # Every declared object type must produce rows, same contract the shipped
    # fixtures are held to.
    empty = [name for name, count in result.object_type_counts.items() if count == 0]
    assert empty == [], f"{connector_name} object types produced no rows: {empty}"


@pytest.mark.parametrize("connector_name", ["github", "slack", "okta", "google_workspace"])
def test_generated_fixtures_are_substantially_larger_than_the_bundled_set(
    connector_name: str, generated: dict[str, Path]
) -> None:
    # The point of generating at all. The bundled sets normalize to well under
    # 100 objects each.
    result = _collect(connector_name, generated[connector_name])
    assert len(result.normalized_objects) > 200


def test_every_timeline_step_names_at_least_one_tenant() -> None:
    for index, (label, by_tenant) in enumerate(TIMELINE):
        assert tenants_at(index), f"step {index} ({label}) drifts nothing"
        assert by_tenant, f"step {index} ({label}) has no tenants"


def test_every_timeline_step_actually_changes_something(generated: dict[str, Path], tmp_path: Path) -> None:
    """A step that resolves nobody returns no notes and silently does nothing."""
    for index, (label, by_tenant) in enumerate(TIMELINE):
        for connector_name in by_tenant:
            staged = tmp_path / f"s{index}-{connector_name}"
            shutil.copytree(generated[connector_name], staged)
            # Replay the earlier steps so this one sees the state it expects.
            apply_steps(staged, steps_for(connector_name, index - 1) if index else [])
            notes = apply_steps(staged, list(by_tenant[connector_name]))
            assert notes, f"step {index} ({label}) produced no drift for {connector_name}"


def test_the_fully_drifted_tree_still_collects(generated: dict[str, Path], tmp_path: Path) -> None:
    # Offboarding removes people; leaving them referenced by a team or a repo
    # would be a dangling relationship the upsert refuses.
    for connector_name in ("github", "slack", "okta"):
        staged = tmp_path / f"final-{connector_name}"
        shutil.copytree(generated[connector_name], staged)
        apply_steps(staged, steps_for(connector_name))
        result = _collect(connector_name, staged)
        assert result.normalized_objects


def test_replaying_the_timeline_twice_is_stable(generated: dict[str, Path], tmp_path: Path) -> None:
    """Steps guard against re-application, so a replay must not double-apply."""
    once = tmp_path / "once"
    shutil.copytree(generated["github"], once)
    apply_steps(once, steps_for("github"))
    first = (once / "members_admin.json").read_text()

    apply_steps(once, steps_for("github"))
    assert (once / "members_admin.json").read_text() == first


def test_the_offboarding_step_leaves_one_account_behind(generated: dict[str, Path], tmp_path: Path) -> None:
    """The cross-app finding the demo is built around needs a survivor.

    Katherine is deprovisioned in Okta, removed from GitHub, and suspended in
    Google Workspace -- and left alone in Slack. If a later edit ever
    offboards her everywhere, `cross-app-departed-still-has-access` has no
    subject and the demo's best beat silently disappears.
    """
    import json

    offboarding_index = next(index for index, (name, _) in enumerate(TIMELINE) if name == "Offboarding")
    katherine = "katherine@acme.example.com"

    drifted: dict[str, Path] = {}
    for tenant in ("okta", "google_workspace", "slack"):
        root = tmp_path / f"survivor-{tenant}"
        shutil.copytree(generated[tenant], root)
        apply_steps(root, steps_for(tenant, upto=offboarding_index))
        drifted[tenant] = root

    okta_users = json.loads((drifted["okta"] / "users.json").read_text())
    okta_row = next(u for u in okta_users if u["profile"]["email"] == katherine)
    assert okta_row["status"] == "DEPROVISIONED"

    gws_users = json.loads((drifted["google_workspace"] / "users.json").read_text())
    gws_row = next(u for u in gws_users if u["primaryEmail"] == katherine)
    assert gws_row["suspended"] is True

    slack_users = json.loads((drifted["slack"] / "users.json").read_text())
    slack_row = next((u for u in slack_users if (u.get("profile") or {}).get("email") == katherine), None)
    assert slack_row is not None, "Katherine must still exist in Slack"
    assert not slack_row.get("deleted"), "Katherine's Slack account must survive offboarding"


def _direct_okta_roles(fixtures_dir: Path) -> dict[str, str]:
    """`{user_id: role}` for the user-assigned Okta roles a collection sees."""
    result = _collect("okta", fixtures_dir)
    return {
        str(raw.payload["user_id"]): str(raw.payload["role_id"])
        for raw in result.raw_objects
        if raw.object_type == "role_assignment" and raw.payload.get("assignment_type") == "USER"
    }


def test_generated_okta_user_roles_are_collected(generated: dict[str, Path]) -> None:
    import json

    # The collector only reads roles for users /iam/assignees lists. A tree
    # whose assignee file names nobody in the directory collects no direct
    # admin at all, and the deprovisioned Super Admin disappears.
    written = {path.stem.removeprefix("user_roles_") for path in generated["okta"].glob("user_roles_*.json")}
    users = {u["id"] for u in json.loads((generated["okta"] / "users.json").read_text())}
    expected = written & users
    assert expected
    assert set(_direct_okta_roles(generated["okta"])) == expected
    assert "SUPER_ADMIN" in _direct_okta_roles(generated["okta"]).values()


def test_the_super_admin_promotion_reaches_the_collector(generated: dict[str, Path], tmp_path: Path) -> None:
    import json

    from kestrel.demo.timeline import ALAN, okta_promote_to_super_admin

    staged = tmp_path / "okta"
    shutil.copytree(generated["okta"], staged)
    alan_id = next(u["id"] for u in json.loads((staged / "users.json").read_text()) if u["profile"]["email"] == ALAN)
    before = _direct_okta_roles(staged)
    assert before.get(alan_id) != "SUPER_ADMIN"

    step = okta_promote_to_super_admin(ALAN)
    assert step(staged)
    assert step(staged), "re-applying the promotion still reports it"
    rows = json.loads((staged / "role_assignees.json").read_text())["value"]
    assert [row["id"] for row in rows].count(alan_id) == 1

    after = _direct_okta_roles(staged)
    assert after[alan_id] == "SUPER_ADMIN"
    assert {k: v for k, v in after.items() if k != alan_id} == {k: v for k, v in before.items() if k != alan_id}


def test_the_super_admin_promotion_leaves_a_missing_assignee_file_missing(
    generated: dict[str, Path], tmp_path: Path
) -> None:
    # No file is an org without /iam/assignees: the collector walks every user
    # and finds the role anyway. Creating the file would hide everyone else.
    from kestrel.demo.timeline import ALAN, okta_promote_to_super_admin

    staged = tmp_path / "okta"
    shutil.copytree(generated["okta"], staged)
    (staged / "role_assignees.json").unlink()
    assert okta_promote_to_super_admin(ALAN)(staged)
    assert not (staged / "role_assignees.json").exists()
    assert "SUPER_ADMIN" in _direct_okta_roles(staged).values()
