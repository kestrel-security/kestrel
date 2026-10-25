# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for pack coverage and enable/disable."""

from __future__ import annotations

import uuid

from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.policies.coverage import compute_pack_coverage, load_connector_capabilities
from kestrel.policies.packs import disable_pack, enable_pack, preview_pack_install


def test_load_connector_capabilities_github() -> None:
    caps = load_connector_capabilities("github")
    assert "github:branch_protection" in caps
    assert "github:org_settings" in caps


def test_pack_coverage_marks_requires(db_session) -> None:
    org = Organization(id=uuid.uuid4(), name="Cov Org", slug="cov-org")
    db_session.add(org)
    db_session.flush()

    coverage = compute_pack_coverage(db_session, org.id, "packs/github-posture")
    assert coverage.pack_name == "github-posture"
    by_slug = {p.slug: p for p in coverage.policies}
    assert "github-repo-default-branch-unprotected" in by_slug
    row = by_slug["github-repo-default-branch-unprotected"]
    assert row.requires == ("github:branch_protection",)
    assert row.status == "not_assessable"
    assert row.reason is not None


def test_enable_disable_pack(db_session) -> None:
    org = Organization(id=uuid.uuid4(), name="Pack Org", slug="pack-org")
    db_session.add(org)
    db_session.flush()

    policy = Policy(
        id=uuid.uuid4(),
        org_id=org.id,
        slug="github-org-2fa-not-required",
        title="Test",
        source=PolicySource.PACK,
        pack_name="github-posture",
    )
    db_session.add(policy)
    db_session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=1,
        source_text="POLICY_ID='x'\nSEVERITY='low'\ndef policy(r): return True",
        severity=Severity.LOW,
        is_enabled=True,
        created_by="test",
    )
    db_session.add(version)
    db_session.flush()
    policy.current_version_id = version.id
    db_session.flush()

    assert disable_pack(db_session, org.id, "github-posture") == 1
    db_session.refresh(version)
    assert version.is_enabled is False
    assert enable_pack(db_session, org.id, "github-posture") == 1
    db_session.refresh(version)
    assert version.is_enabled is True


def test_install_preview_unassessable(db_session) -> None:
    org = Organization(id=uuid.uuid4(), name="Preview Org", slug="preview-org")
    db_session.add(org)
    db_session.flush()
    preview = preview_pack_install(db_session, org.id, "packs/github-posture")
    assert preview.unassessable
