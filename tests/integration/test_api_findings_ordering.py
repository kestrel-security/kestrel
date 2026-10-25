# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the default ordering of `GET /findings`.

Every finding from one policy evaluation is stamped with a single
timestamp, so ordering by time alone groups the list by policy: the first
screen becomes ten copies of one title, and a lone critical sits below a wall
of mediums. The default is `severity DESC, first_seen_at DESC, id DESC`.

Postgres orders a native enum by declaration order (`low` -> `critical`), which
is why this needs no CASE expression -- and why it is worth a test that would
catch the column being changed to a plain string, where `DESC` would silently
become alphabetical and put `low` above `high`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kestrel.db.models.finding import Finding
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.org import Organization
from kestrel.testing import api_client, make_organization
from sqlalchemy import update
from sqlalchemy.orm import Session

from tests.integration.test_api_factories import make_findings_batch

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def _seed_one_of_each(session: Session, org: Organization) -> int:
    """One batch per severity, seeded worst-FIRST on purpose, so the worst
    findings are also the *oldest*.

    This matters: seeded the other way, chronological order and severity order
    coincide, and a test asserting "worst first" passes even against the plain
    `last_seen_at DESC` ordering -- proving nothing. Seeded this way the two
    orderings are exact opposites, so only the ranked one can pass.

    Returns the total number of findings, which is not `2 * 4`. Each batch's
    policy is evaluated against every identity in the org, including the ones
    earlier batches created, so the counts compound. That is a property of the
    factory, not of the endpoint -- these tests assert on ordering, which is
    what is actually under test.
    """
    total = 0
    for i, severity in enumerate(SEVERITY_ORDER, start=1):
        make_findings_batch(session, org, 2, severity=severity)
        total += 2 * i
    return total


def _is_worst_first(severities: list[str]) -> bool:
    ranks = [RANK[s] for s in severities]
    return ranks == sorted(ranks)


def _client(session: Session, org: Organization):
    return api_client(session, OperatorRole.READ_ONLY, org=org)


def test_default_order_is_worst_first(db_session: Session) -> None:
    org = make_organization(db_session)
    total = _seed_one_of_each(db_session, org)

    with _client(db_session, org) as client:
        body = client.get(f"/api/v1/findings?limit={total}").json()

    severities = [f["severity"] for f in body["items"]]
    assert len(severities) == total
    assert set(severities) == set(SEVERITY_ORDER), "the fixture must cover every severity"
    assert _is_worst_first(severities), severities
    assert severities[0] == "critical"
    assert severities[-1] == "low"


def test_a_lone_critical_is_not_buried_by_newer_mediums(db_session: Session) -> None:
    """The failure this ordering exists to prevent."""
    org = make_organization(db_session)
    make_findings_batch(db_session, org, 1, severity="critical")
    # Evaluated later, so strictly newer by last_seen_at.
    make_findings_batch(db_session, org, 25, severity="medium")

    with _client(db_session, org) as client:
        body = client.get("/api/v1/findings?limit=10").json()

    assert body["items"][0]["severity"] == "critical"


@pytest.mark.parametrize("sort", ["newest", "last_seen"])
def test_sort_newest_restores_the_chronological_order(db_session: Session, sort: str) -> None:
    """`last_seen` is kept as an alias of `newest` for existing clients."""
    org = make_organization(db_session)
    make_findings_batch(db_session, org, 1, severity="critical")
    make_findings_batch(db_session, org, 3, severity="low")

    with _client(db_session, org) as client:
        body = client.get(f"/api/v1/findings?sort={sort}").json()

    # The low batch was detected second, so it is the most recent.
    assert body["items"][0]["severity"] == "low"


@pytest.mark.parametrize("sort", ["severity", "newest"])
def test_an_evaluation_between_pages_does_not_skip_findings(db_session: Session, sort: str) -> None:
    """Every evaluation bumps `last_seen_at`. A cursor on that column skipped
    every still-open finding touched between two page fetches."""
    org = make_organization(db_session)
    total = _seed_one_of_each(db_session, org)

    seen: list[str] = []
    cursor: str | None = None
    with _client(db_session, org) as client:
        for page in range(total + 2):
            url = f"/api/v1/findings?sort={sort}&limit=3" + (f"&cursor={cursor}" if cursor else "")
            body = client.get(url).json()
            seen.extend(f["id"] for f in body["items"])
            cursor = body["next_cursor"]
            if cursor is None:
                break
            if page == 0:
                # An evaluation lands between page 1 and page 2.
                db_session.execute(
                    update(Finding)
                    .where(Finding.org_id == org.id)
                    .values(last_seen_at=datetime.now(UTC) + timedelta(minutes=5))
                )
                db_session.flush()

    assert len(seen) == total
    assert len(set(seen)) == total


def test_an_unknown_sort_is_rejected_rather_than_ignored(db_session: Session) -> None:
    org = make_organization(db_session)

    with _client(db_session, org) as client:
        assert client.get("/api/v1/findings?sort=priority").status_code == 422


def test_paging_the_ranked_order_visits_every_finding_once(db_session: Session) -> None:
    """Keyset pagination across a three-part sort key is where an ordering
    change most plausibly breaks: a page boundary that falls inside one
    severity must not repeat or skip rows."""
    org = make_organization(db_session)
    total = _seed_one_of_each(db_session, org)

    seen: list[str] = []
    severities: list[str] = []
    cursor: str | None = None
    with _client(db_session, org) as client:
        for _ in range(total + 2):  # generous bound; terminates on next_cursor
            url = "/api/v1/findings?limit=3" + (f"&cursor={cursor}" if cursor else "")
            body = client.get(url).json()
            seen.extend(f["id"] for f in body["items"])
            severities.extend(f["severity"] for f in body["items"])
            cursor = body["next_cursor"]
            if cursor is None:
                break

    assert cursor is None, "pagination did not terminate"
    assert len(seen) == total
    assert len(set(seen)) == total, "a finding was returned on more than one page"
    # Ordering holds across page boundaries, not just within a page.
    assert _is_worst_first(severities), severities
