# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- dry run and verify past the match limit.

`match_limit` caps the returned payload only. Counts, "would resolve" and
verify's "still matches" use every match.
"""

from __future__ import annotations

import pytest
from kestrel.findings.verify import verify_finding_remediation
from kestrel.policies.dry_run import dry_run_policy
from sqlalchemy.orm import Session

from tests.integration.finding_world import FindingWorld

# --- #12: verify / dry-run past the match limit ----------------------------


def test_dry_run_counts_use_every_match_not_the_truncated_payload(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy()
    world.evaluate()

    dry = dry_run_policy(db_session, world.org.id, policy, match_limit=1)

    assert dry["truncated"] is True
    assert len(dry["matches"]) == 1
    assert dry["would_resolve_count"] == 0
    assert dry["existing_match_count"] == 2
    assert dry["new_match_count"] == 0


def test_verify_finds_a_subject_beyond_the_match_limit(db_session: Session, monkeypatch: pytest.MonkeyPatch):
    import kestrel.policies.dry_run as dry_run_module

    monkeypatch.setattr(dry_run_module, "MATCH_CAP", 1)
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy()
    world.evaluate()

    results = {verify_finding_remediation(db_session, f)["result"] for f in world.findings(policy)}

    assert results == {"still_matches"}
