# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The cross-app pack's fixture files are generated from
`kestrel.policies.cross_app_fixtures`; the AI generator and the deterministic
templates read the same module, so the three must never disagree."""

from __future__ import annotations

import json

import pytest
from kestrel.policies.cross_app_fixtures import CROSS_APP_FIXTURE_SETS
from kestrel.policies.fixture_builders import account, build_rows, person
from kestrel.policies.packs import get_packs_dir


@pytest.mark.parametrize("slug", sorted(CROSS_APP_FIXTURE_SETS))
def test_pack_fixture_file_matches_the_generator(slug: str) -> None:
    path = get_packs_dir() / "cross-app" / "policies" / "fixtures" / f"{slug}.fixtures.json"
    assert path.is_file(), f"run scripts/gen-cross-app-fixtures.py to create {path.name}"
    stored = json.loads(path.read_text())
    generated = json.loads(json.dumps(CROSS_APP_FIXTURE_SETS[slug]))
    assert stored == generated, f"{path.name} is stale: run scripts/gen-cross-app-fixtures.py"


def test_every_row_of_a_person_carries_the_same_cluster() -> None:
    rows = build_rows(
        [
            person(
                "pat",
                "pat@vendor.example",
                account("okta", days_ago=3, mfa=False),
                account("github", days_ago=None, roles=("organization_admin",)),
                worker_type="contractor",
            )
        ]
    )
    assert [row["_subject_id"] for row in rows] == ["pat-okta", "pat-github"]
    okta, github = rows
    assert okta["cluster"] == {**github["cluster"], "is_representative": True}
    assert github["cluster"]["is_representative"] is False
    assert okta["cluster"]["representative_identity_id"] == "pat-okta"
    assert okta["cluster"]["worker_type"] == "contractor"
    assert okta["cluster"]["idp_status"] == "active"
    assert okta["cluster"]["privileged_application_types"] == ["github"]
    assert okta["cluster"]["last_active_at"] == {"$days_ago": 3}
    assert github["identity"]["last_active_at"] is None
    assert [a["identity_id"] for a in okta["cluster"]["accounts"]] == ["pat-okta", "pat-github"]


def test_builder_rows_carry_every_key_the_loader_emits() -> None:
    """The documented identity row shape is the contract AI drafts are checked
    against; a builder row must not lack a key a real row has."""
    row = build_rows([person("x", "x@acme.example", account("okta", days_ago=1))])[0]
    assert {
        "_subject_id",
        "_subject_type",
        "identity",
        "application",
        "roles",
        "groups",
        "oauth_grants",
        "cluster",
        "org",
    } <= set(row)
    account_keys = set(row["cluster"]["accounts"][0])
    assert {
        "identity_id",
        "application_type",
        "is_disabled",
        "mfa_enabled",
        "last_active_at",
        "last_active_source",
        "worker_type",
        "roles",
        "privileged",
        "groups",
        "disabled_at",
        "expires_at",
    } <= account_keys
    assert {
        "idp_status",
        "idp_application_types",
        "privileged_application_types",
        "representative_identity_id",
        "worker_type",
        "last_active_at",
        "is_representative",
        "member_count",
    } <= set(row["cluster"])
