# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""One cursor-pagination contract, applied to every endpoint built on
`kestrel_api.pagination.apply_keyset` / `build_page`
(`GET /audit-log`, `GET /identities`, `GET /findings` -- found by grepping
the routers for those two names). Endpoints that page by plain
`limit`/`offset` instead (`GET /changes`) are a different, simpler contract
and are not in scope here.

Each case below is parametrized across `ENDPOINTS`; adding a fourth
keyset-paginated endpoint means adding one `PaginatedEndpoint` row and one
`seed` function, not a new test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.org import Organization
from kestrel.testing import api_client, make_operator, make_organization
from sqlalchemy.orm import Session

from tests.integration.test_api_factories import make_findings_batch, make_identity

PAGE_LIMIT = 5


def _seed_audit_log(session: Session, org: Organization, n: int) -> None:
    """`AuditLog.created_at` is `server_default=func.now()`; every row
    inserted in this test's savepoint transaction shares one Postgres
    transaction timestamp, so `n` calls here naturally collide on the sort
    key -- exactly the "duplicate sort keys" case the contract requires."""
    operator = make_operator(session, org)
    for i in range(n):
        record_audit_event(session, org_id=org.id, actor_operator_id=operator.id, action=f"pagination_probe.{i}")
    session.flush()


def _seed_identities(session: Session, org: Organization, n: int) -> None:
    """`Identity.created_at` is likewise `server_default=func.now()` --
    same free duplicate-timestamp effect as the audit log."""
    for _ in range(n):
        make_identity(session, org)


def _seed_findings(session: Session, org: Organization, n: int) -> None:
    """Finding.last_seen_at is assigned in application code from one shared
    `datetime.now(UTC)` per evaluation batch -- see make_findings_batch."""
    make_findings_batch(session, org, n)


@dataclass
class PaginatedEndpoint:
    name: str
    path: str
    role: OperatorRole
    seed: Callable[[Session, Organization, int], None]
    items_key: str = "items"


ENDPOINTS: list[PaginatedEndpoint] = [
    PaginatedEndpoint("audit_log", "/api/v1/audit-log", OperatorRole.ADMIN, _seed_audit_log),
    PaginatedEndpoint("identities", "/api/v1/identities", OperatorRole.READ_ONLY, _seed_identities),
    PaginatedEndpoint("findings", "/api/v1/findings", OperatorRole.READ_ONLY, _seed_findings),
]


def _ids() -> list[str]:
    return [e.name for e in ENDPOINTS]


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_ids())
def test_exact_page_size_boundary(db_session, endpoint: PaginatedEndpoint):
    """Exactly `limit` rows: one full page, and `next_cursor` is null --
    `apply_keyset` over-fetches `limit + 1` precisely so this doesn't
    misreport a phantom next page."""
    org = make_organization(db_session)
    endpoint.seed(db_session, org, PAGE_LIMIT)
    client = api_client(db_session, endpoint.role, org=org)

    response = client.get(endpoint.path, params={"limit": PAGE_LIMIT})

    assert response.status_code == 200
    body = response.json()
    assert len(body[endpoint.items_key]) == PAGE_LIMIT
    assert body["next_cursor"] is None


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_ids())
def test_pages_through_with_duplicate_sort_keys_no_gaps_or_repeats(db_session, endpoint: PaginatedEndpoint):
    """More rows than fit on one page, all sharing a sort-key value (see the
    seed functions above): walking `next_cursor` to the end must visit every
    row exactly once, in full pages until the remainder."""
    total = PAGE_LIMIT * 2 + 3
    org = make_organization(db_session)
    endpoint.seed(db_session, org, total)
    client = api_client(db_session, endpoint.role, org=org)

    seen_ids: list[str] = []
    page_sizes: list[int] = []
    cursor: str | None = None
    for _ in range(10):  # hard stop so a broken cursor can't hang the test
        params = {"limit": PAGE_LIMIT}
        if cursor is not None:
            params["cursor"] = cursor
        response = client.get(endpoint.path, params=params)
        assert response.status_code == 200
        body = response.json()
        page = body[endpoint.items_key]
        page_sizes.append(len(page))
        seen_ids.extend(item["id"] for item in page)
        cursor = body["next_cursor"]
        if cursor is None:
            break
    else:
        pytest.fail("did not reach a null next_cursor within 10 pages")

    assert len(seen_ids) == total, "row count changed while paging"
    assert len(set(seen_ids)) == total, "a row was repeated across pages"
    assert page_sizes[:-1] == [PAGE_LIMIT] * (len(page_sizes) - 1), "a non-final page was short"
    assert 1 <= page_sizes[-1] <= PAGE_LIMIT


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_ids())
def test_malformed_cursor_is_rejected(db_session, endpoint: PaginatedEndpoint):
    org = make_organization(db_session)
    client = api_client(db_session, endpoint.role, org=org)

    response = client.get(endpoint.path, params={"cursor": "not-a-valid-cursor!!"})

    assert response.status_code == 422


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_ids())
def test_limit_is_clamped_not_rejected(db_session, endpoint: PaginatedEndpoint):
    """`normalize_limit` clamps to `MAX_LIMIT` (200) rather than erroring --
    an oversized `limit` must not turn into an unbounded query or a 4xx."""
    org = make_organization(db_session)
    endpoint.seed(db_session, org, 1)
    client = api_client(db_session, endpoint.role, org=org)

    response = client.get(endpoint.path, params={"limit": 999_999})

    assert response.status_code == 200
    assert len(response.json()[endpoint.items_key]) == 1


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_ids())
def test_limit_below_one_is_rejected(db_session, endpoint: PaginatedEndpoint):
    org = make_organization(db_session)
    client = api_client(db_session, endpoint.role, org=org)

    response = client.get(endpoint.path, params={"limit": 0})

    assert response.status_code == 422
