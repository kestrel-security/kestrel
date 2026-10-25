# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack catalog behavior beyond the auth matrix: install-preview diff and
install idempotency. Uses real on-disk packs (`packs/github-posture`) --
real product data, not a fixture persona -- since the pack catalog is
file-owned and has no factory equivalent.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_install_preview_reports_added_policies_before_install(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/packs/github-posture/install-preview")

    assert response.status_code == 200
    body = response.json()
    assert body["added"], "a never-installed pack should show every policy as added"
    assert body["updated"] == []
    assert body["unchanged"] == []


def test_install_then_reinstall_is_idempotent(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    first = client.post("/api/v1/packs/github-posture/install")
    assert first.status_code == 200
    first_versions = {row["slug"]: row["current_version_id"] for row in first.json()}

    preview_after = client.get("/api/v1/packs/github-posture/install-preview")
    assert preview_after.status_code == 200
    assert preview_after.json()["added"] == []
    assert preview_after.json()["updated"] == []
    assert set(preview_after.json()["unchanged"]) == set(first_versions)

    second = client.post("/api/v1/packs/github-posture/install")
    assert second.status_code == 200
    second_versions = {row["slug"]: row["current_version_id"] for row in second.json()}

    # Unchanged source text -> no new PolicyVersion, same current_version_id.
    assert second_versions == first_versions


def test_get_pack_marks_installed_policies(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    installed = client.post("/api/v1/packs/github-posture/install")
    assert installed.status_code == 200

    response = client.get("/api/v1/packs/github-posture")

    assert response.status_code == 200
    body = response.json()
    assert body["installed"] is True
    assert all(row["installed"] for row in body["policies"])


def test_unknown_pack_name_is_404(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/packs/does-not-exist-anywhere")

    assert response.status_code == 404


def test_list_packs_reflects_install_state(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    before = client.get("/api/v1/packs")
    assert before.status_code == 200
    before_row = next(p for p in before.json() if p["name"] == "github-posture")
    assert before_row["installed"] is False

    client.post("/api/v1/packs/github-posture/install")

    after = client.get("/api/v1/packs")
    after_row = next(p for p in after.json() if p["name"] == "github-posture")
    assert after_row["installed"] is True


def test_a_policy_maps_to_a_control_another_pack_defines(db_session):
    """Compliance controls install shared, so a mapping may cross packs.

    `cross-app` claims the internal control GH-01, which only `github-posture` defines.
    Resolving the claim against the current pack's catalog alone dropped that
    mapping silently: the policy installed with no compliance coverage, and the
    pack page showed a framework it did not actually cover.
    """
    from kestrel.db.models.compliance import ComplianceControl, PolicyControlMapping
    from kestrel.db.models.policy import Policy
    from sqlalchemy import select

    client = api_client(db_session, OperatorRole.ANALYST)
    assert client.post("/api/v1/packs/github-posture/install").status_code == 200
    assert client.post("/api/v1/packs/cross-app/install").status_code == 200

    org_id = client.kestrel_org.id
    policy = db_session.scalars(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.slug == "cross-app-privileged-concentration",
        )
    ).one()
    control = db_session.scalars(
        select(ComplianceControl).where(
            ComplianceControl.org_id.is_(None),
            ComplianceControl.control_id == "GH-01",
        )
    ).one()
    mapping = db_session.scalars(
        select(PolicyControlMapping).where(
            PolicyControlMapping.policy_id == policy.id,
            PolicyControlMapping.compliance_control_id == control.id,
        )
    ).one_or_none()

    assert mapping is not None
