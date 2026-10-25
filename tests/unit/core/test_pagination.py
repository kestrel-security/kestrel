# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel_api.pagination`: opaque keyset cursors, limit clamping, and page
assembly. `apply_keyset` builds a SQLAlchemy `Select` -- these tests only
compile it (via `str()`), never execute it, so no database is touched.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from kestrel_api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Cursor,
    apply_keyset,
    build_page,
    decode_cursor,
    encode_cursor,
    normalize_limit,
)
from sqlalchemy import Column, DateTime, Uuid, select
from sqlalchemy.orm import DeclarativeBase


class _Base(DeclarativeBase):
    pass


class _Widget(_Base):
    __tablename__ = "pagination_test_widgets"

    id = Column(Uuid, primary_key=True)
    created_at = Column(DateTime(timezone=True))


class _Row:
    """A plain object with the two attributes `build_page` reads off a row."""

    def __init__(self, sort_value: datetime, row_id: uuid.UUID) -> None:
        self.sort_value = sort_value
        self.id = row_id


def test_cursor_round_trips_sort_value_and_id():
    sort_value = datetime(2026, 1, 15, 12, 30, tzinfo=UTC)
    row_id = uuid.uuid4()

    cursor = encode_cursor(sort_value, row_id)
    decoded = decode_cursor(cursor)

    assert isinstance(decoded, Cursor)
    assert decoded.sort_value == sort_value
    assert decoded.id == row_id


def test_cursor_is_opaque_base64url_without_padding():
    cursor = encode_cursor(datetime(2026, 1, 1, tzinfo=UTC), uuid.uuid4())

    assert "=" not in cursor
    # Must be decodable as urlsafe base64 once padding is restored.
    padded = cursor + "=" * (-len(cursor) % 4)
    base64.urlsafe_b64decode(padded.encode())


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-valid-base64!!!",
        base64.urlsafe_b64encode(b"not json").decode().rstrip("="),
        base64.urlsafe_b64encode(b'{"v": "2026-01-01T00:00:00+00:00"}').decode().rstrip("="),  # no id
        base64.urlsafe_b64encode(b'{"id": "not-a-uuid", "v": "2026-01-01T00:00:00+00:00"}').decode().rstrip("="),
        base64.urlsafe_b64encode(b'{"v": "not-a-datetime", "id": "3f1c9c2e-2a2b-4b3e-9b8d-6a2f1e2c3d4a"}')
        .decode()
        .rstrip("="),
    ],
)
def test_malformed_cursors_raise_422_instead_of_falling_through(malformed):
    with pytest.raises(HTTPException) as exc_info:
        decode_cursor(malformed)

    assert exc_info.value.status_code == 422


def test_normalize_limit_of_none_uses_the_default():
    assert normalize_limit(None) == DEFAULT_LIMIT


def test_normalize_limit_clamps_to_the_maximum():
    assert normalize_limit(MAX_LIMIT + 1000) == MAX_LIMIT


def test_normalize_limit_passes_through_a_value_within_range():
    assert normalize_limit(10) == 10


def test_normalize_limit_at_exactly_the_maximum_is_unchanged():
    assert normalize_limit(MAX_LIMIT) == MAX_LIMIT


def test_normalize_limit_of_one_is_accepted():
    assert normalize_limit(1) == 1


def test_normalize_limit_of_zero_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        normalize_limit(0)
    assert exc_info.value.status_code == 422


def test_normalize_limit_of_a_negative_value_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        normalize_limit(-5)
    assert exc_info.value.status_code == 422


def test_build_page_reports_no_next_cursor_when_rows_fit_within_the_limit():
    rows = [_Row(datetime(2026, 1, i + 1, tzinfo=UTC), uuid.uuid4()) for i in range(3)]

    page = build_page(rows, limit=5, sort_attr="sort_value", serializer=lambda r: str(r.id))

    assert len(page["items"]) == 3
    assert page["next_cursor"] is None


def test_build_page_trims_the_sentinel_row_and_emits_a_next_cursor():
    rows = [_Row(datetime(2026, 1, i + 1, tzinfo=UTC), uuid.uuid4()) for i in range(6)]

    page = build_page(rows, limit=5, sort_attr="sort_value", serializer=lambda r: str(r.id))

    assert len(page["items"]) == 5
    assert page["next_cursor"] is not None
    decoded = decode_cursor(page["next_cursor"])
    assert decoded.sort_value == rows[4].sort_value
    assert decoded.id == rows[4].id


def test_build_page_of_an_empty_result_set():
    page = build_page([], limit=5, sort_attr="sort_value", serializer=lambda r: str(r.id))

    assert page == {"items": [], "next_cursor": None}


def test_apply_keyset_without_a_cursor_orders_and_limits_by_one_extra_row():
    stmt = apply_keyset(
        select(_Widget),
        sort_column=_Widget.created_at,
        id_column=_Widget.id,
        cursor=None,
        limit=DEFAULT_LIMIT,
    )

    compiled = str(stmt.compile())
    assert "ORDER BY" in compiled
    assert f"LIMIT {DEFAULT_LIMIT + 1}" in compiled or "LIMIT :param" in compiled


def test_apply_keyset_with_a_cursor_adds_the_row_value_predicate():
    cursor = encode_cursor(datetime(2026, 1, 1, tzinfo=UTC), uuid.uuid4())

    stmt = apply_keyset(
        select(_Widget),
        sort_column=_Widget.created_at,
        id_column=_Widget.id,
        cursor=cursor,
        limit=DEFAULT_LIMIT,
    )

    compiled = str(stmt.compile())
    assert "WHERE" in compiled


def test_apply_keyset_with_a_malformed_cursor_raises_422_before_touching_the_query():
    with pytest.raises(HTTPException) as exc_info:
        apply_keyset(
            select(_Widget),
            sort_column=_Widget.created_at,
            id_column=_Widget.id,
            cursor="not-a-valid-cursor!!!",
            limit=DEFAULT_LIMIT,
        )
    assert exc_info.value.status_code == 422
