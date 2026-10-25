# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack install-preview, profile filtering, coverage, and enable/disable.

Every test builds its own pack catalog under `tmp_path` and points
`KESTREL_PACKS_DIR` at it, so nothing here depends on a shipped pack's
contents.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.webhook import FINDING_RESOLVED
from kestrel.testing import api_client
from sqlalchemy import select

from tests.integration.test_api_factories import FakeTaskQueue, make_finding, make_identity, make_webhook

_POLICY = """\
POLICY_ID = "{slug}"
TITLE = "{title}"
SEVERITY = "{severity}"
RESOURCE_TYPE = "identity"
PROFILE = "{profile}"
DESCRIPTION = "Test pack policy."
REMEDIATION = "n/a"


def policy(resource):
    return False
"""


def _write_pack(root: Path, name: str, policies: list[dict]) -> None:
    pack_dir = root / name
    (pack_dir / "policies").mkdir(parents=True)
    slugs = "\n".join(f"  - {p['slug']}" for p in policies)
    (pack_dir / "pack.yaml").write_text(f'name: {name}\nversion: "1.0.0"\ndescription: Test pack\npolicies:\n{slugs}\n')
    for p in policies:
        body = _POLICY.format(
            slug=p["slug"],
            title=p.get("title", p["slug"]),
            severity=p.get("severity", "medium"),
            profile=p.get("profile", "level_1"),
        )
        (pack_dir / "policies" / f"{p['slug'].replace('-', '_')}.py").write_text(body)


@pytest.fixture
def pack(tmp_path, monkeypatch):
    """A two-policy pack (one level_1, one level_2) in an isolated catalog."""
    name = f"test-pack-{uuid.uuid4().hex[:8]}"
    first = f"{name}-alpha"
    second = f"{name}-beta"
    _write_pack(tmp_path, name, [{"slug": first}, {"slug": second, "profile": "level_2", "severity": "high"}])
    monkeypatch.setenv("KESTREL_PACKS_DIR", str(tmp_path))
    return {"name": name, "root": tmp_path, "slugs": [first, second]}


def _enabled_by_slug(session, org_id) -> dict[str, bool]:
    rows = session.execute(
        select(Policy.slug, PolicyVersion.is_enabled)
        .join(PolicyVersion, PolicyVersion.id == Policy.current_version_id)
        .where(Policy.org_id == org_id)
    ).all()
    return dict(rows)


def test_preview_classifies_added_then_unchanged_then_updated(db_session, pack):
    client = api_client(db_session, OperatorRole.ANALYST)
    url = f"/api/v1/packs/{pack['name']}/install-preview"

    before = client.get(url)
    assert before.status_code == 200
    assert before.json()["installed"] is False
    assert sorted(before.json()["added"]) == sorted(pack["slugs"])

    assert client.post(f"/api/v1/packs/{pack['name']}/install").status_code == 200
    after = client.get(url).json()
    assert after["installed"] is True
    assert after["added"] == []
    assert sorted(after["unchanged"]) == sorted(pack["slugs"])

    # Edit one policy's title on disk: the preview now reports it as updated.
    alpha = pack["slugs"][0]
    path = pack["root"] / pack["name"] / "policies" / f"{alpha.replace('-', '_')}.py"
    path.write_text(path.read_text().replace(f'TITLE = "{alpha}"', 'TITLE = "A new title"'))
    edited = client.get(url).json()
    assert edited["updated"] == [alpha]
    assert edited["unchanged"] == [pack["slugs"][1]]


def test_preview_and_install_honour_the_profile_filter(db_session, pack):
    client = api_client(db_session, OperatorRole.ANALYST)

    preview = client.get(f"/api/v1/packs/{pack['name']}/install-preview", params={"profile": "level_2"})
    assert preview.json()["added"] == [pack["slugs"][1]]

    installed = client.post(f"/api/v1/packs/{pack['name']}/install", json={"profile": "level_1"})
    assert installed.status_code == 200
    assert [p["slug"] for p in installed.json()] == [pack["slugs"][0]]


def test_preview_and_install_reject_a_pack_with_an_invalid_policy(db_session, pack):
    broken = pack["root"] / pack["name"] / "policies" / "zz_broken.py"
    broken.write_text('POLICY_ID = "broken"\nimport os\n')
    client = api_client(db_session, OperatorRole.ANALYST)

    preview = client.get(f"/api/v1/packs/{pack['name']}/install-preview")
    install = client.post(f"/api/v1/packs/{pack['name']}/install")

    assert preview.status_code == 400
    assert install.status_code == 400
    assert "broken" in install.json()["detail"]


@pytest.mark.parametrize("suffix", ["install-preview", "coverage"])
def test_unknown_pack_is_404_on_get_routes(db_session, pack, suffix):
    client = api_client(db_session, OperatorRole.ANALYST)

    assert client.get(f"/api/v1/packs/no-such-pack/{suffix}").status_code == 404


@pytest.mark.parametrize("action", ["install", "enable", "disable"])
def test_unknown_pack_is_404_on_post_routes(db_session, pack, action):
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=FakeTaskQueue())

    assert client.post(f"/api/v1/packs/no-such-pack/{action}").status_code == 404


def test_coverage_lists_every_pack_policy(db_session, pack):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get(f"/api/v1/packs/{pack['name']}/coverage")

    assert response.status_code == 200
    assert pack["name"] in response.text
    for slug in pack["slugs"]:
        assert slug in response.text


def test_disable_then_enable_toggles_every_pack_policy(db_session, pack):
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=FakeTaskQueue())
    org_id = client.kestrel_org.id
    client.post(f"/api/v1/packs/{pack['name']}/install")

    disabled = client.post(f"/api/v1/packs/{pack['name']}/disable")
    assert disabled.status_code == 200
    assert disabled.json() == {"pack_name": pack["name"], "policies_updated": 2, "enabled": False}
    assert set(_enabled_by_slug(db_session, org_id).values()) == {False}

    # Idempotent: nothing left to disable.
    assert client.post(f"/api/v1/packs/{pack['name']}/disable").json()["policies_updated"] == 0

    enabled = client.post(f"/api/v1/packs/{pack['name']}/enable")
    assert enabled.status_code == 200
    assert enabled.json() == {"pack_name": pack["name"], "policies_updated": 2, "enabled": True}
    assert set(_enabled_by_slug(db_session, org_id).values()) == {True}


def test_disable_resolves_open_findings_and_enqueues_webhooks(db_session, pack):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    org = client.kestrel_org
    client.post(f"/api/v1/packs/{pack['name']}/install", json={"profile": "level_1"})
    policy = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == pack["slugs"][0])).one()
    make_webhook(db_session, org, url="https://93.184.216.34/hook", events=[FINDING_RESOLVED])
    finding = make_finding(db_session, org, identity=make_identity(db_session, org), policy=policy)
    db_session.commit()
    assert finding.status == FindingStatus.OPEN

    response = client.post(f"/api/v1/packs/{pack['name']}/disable")

    assert response.status_code == 200
    db_session.expire_all()
    assert db_session.get(Finding, finding.id).status == FindingStatus.RESOLVED
    assert len(tasks.webhook_deliveries) == 1


def test_read_only_cannot_toggle_packs(db_session, pack):
    client = api_client(db_session, OperatorRole.READ_ONLY, task_queue=FakeTaskQueue())

    assert client.post(f"/api/v1/packs/{pack['name']}/enable").status_code == 403
    assert client.post(f"/api/v1/packs/{pack['name']}/disable").status_code == 403
