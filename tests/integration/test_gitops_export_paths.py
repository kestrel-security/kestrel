# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Analyst-authored and legacy policy IDs must not escape a GitOps export."""

from pathlib import Path

import pytest
from kestrel.db.models.operator import OperatorRole
from kestrel.gitops import GitOpsError, export_org_state
from kestrel.policies.authoring import create_custom_policy
from kestrel.testing import api_client


def _source(slug: str) -> str:
    return f"POLICY_ID = {slug!r}\nSEVERITY = 'low'\ndef policy(resource):\n    return False\n"


@pytest.mark.parametrize("slug", ["../../outside", "/tmp/outside", r"..\outside", "a/b", "a.b", "a" * 129])
def test_analyst_cannot_store_a_filename_unsafe_policy_id(db_session, tmp_path: Path, slug: str) -> None:
    client = api_client(db_session, OperatorRole.ANALYST)
    sentinel = tmp_path / "outside.py"
    sentinel.write_text("keep me")

    response = client.post("/api/v1/policies", json={"source_text": _source(slug)})

    assert response.status_code == 400
    export_org_state(db_session, client.kestrel_org.id, tmp_path / "export")
    assert sentinel.read_text() == "keep me"


def test_export_rejects_a_legacy_unsafe_slug_before_writing(db_session, tmp_path: Path) -> None:
    client = api_client(db_session)
    policy = create_custom_policy(db_session, org_id=client.kestrel_org.id, source_text=_source("valid-policy"))
    policy.slug = "../../outside"
    db_session.flush()
    sentinel = tmp_path / "outside.py"
    sentinel.write_text("keep me")

    with pytest.raises(GitOpsError, match="POLICY_ID"):
        export_org_state(db_session, client.kestrel_org.id, tmp_path / "export")

    assert sentinel.read_text() == "keep me"


@pytest.mark.parametrize("symlink", ["policies", "policies/valid_policy.py", "kestrel.yaml"])
def test_export_does_not_follow_existing_symlinks(db_session, tmp_path: Path, symlink: str) -> None:
    client = api_client(db_session)
    create_custom_policy(db_session, org_id=client.kestrel_org.id, source_text=_source("valid-policy"))
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("keep me")
    output = tmp_path / "export"
    output.mkdir()
    if symlink == "policies":
        (output / symlink).symlink_to(outside, target_is_directory=True)
    else:
        (output / "policies").mkdir()
        (output / symlink).symlink_to(sentinel)

    with pytest.raises(GitOpsError):
        export_org_state(db_session, client.kestrel_org.id, output)

    assert sentinel.read_text() == "keep me"
    assert sorted(p.name for p in outside.iterdir()) == ["sentinel"]


def test_export_rejects_colliding_filenames_without_overwriting(db_session, tmp_path: Path) -> None:
    client = api_client(db_session)
    for slug in ("same-name", "same_name"):
        create_custom_policy(db_session, org_id=client.kestrel_org.id, source_text=_source(slug))
    output = tmp_path / "export"
    (output / "policies").mkdir(parents=True)
    sentinel = output / "policies/same_name.py"
    sentinel.write_text("keep me")

    with pytest.raises(GitOpsError, match="same export filename"):
        export_org_state(db_session, client.kestrel_org.id, output)

    assert sentinel.read_text() == "keep me"
