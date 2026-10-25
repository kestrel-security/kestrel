# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Keyset (cursor) pagination for list endpoints.

Keyset rather than limit/offset: offset pagination re-scans skipped rows and,
worse, silently drops or duplicates items when rows are inserted or removed
between page fetches -- which for a continuously-syncing inventory is the
normal case, not an edge case. Keyset pagination anchors each page to the
last row's sort key, so concurrent writes shift what comes next instead of
corrupting the sequence.

Every paginated endpoint sorts by `(<timestamp column> DESC, id DESC)`. The
id tiebreaker is required for correctness, not neatness: timestamps collide
routinely (a sync writes many rows in the same transaction), and without a
unique tiebreaker the keyset comparison would skip or repeat the colliding
rows. The comparison uses a SQL row-value expression -- `(ts, id) < (:ts,
:id)` -- which Postgres can satisfy with a plain composite index.

Cursors are opaque base64url-encoded JSON. Clients must treat them as
meaningless strings: the encoding is an implementation detail and may change
without a version bump.
"""

from __future__ import annotations

import base64
import binascii
import enum
import json
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, NamedTuple

from fastapi import HTTPException
from sqlalchemy import Select, tuple_
from sqlalchemy.orm import InstrumentedAttribute

# Keeps a single oversized `limit` from turning into an unbounded query.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


class Cursor(NamedTuple):
    sort_value: datetime
    id: uuid.UUID
    # Only set for endpoints that rank ahead of the timestamp (see `rank_column`).
    rank: str | None = None


def encode_cursor(sort_value: datetime, row_id: uuid.UUID, rank: str | None = None) -> str:
    payload: dict[str, str] = {"v": sort_value.isoformat(), "id": str(row_id)}
    if rank is not None:
        payload["r"] = rank
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> Cursor:
    """Raises 422 for anything malformed -- a bad cursor is a client error,
    and must not fall through to an unpaginated full-table scan.

    `r` is optional so cursors minted before ranked ordering existed still
    decode; an unranked cursor against a ranked endpoint simply restarts from
    the timestamp boundary rather than 422-ing a client mid-pagination.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return Cursor(
            sort_value=datetime.fromisoformat(data["v"]),
            id=uuid.UUID(data["id"]),
            rank=data.get("r"),
        )
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail=f"Malformed cursor: {exc}") from exc


def normalize_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1:
        raise HTTPException(status_code=422, detail="limit must be >= 1")
    return min(limit, MAX_LIMIT)


def apply_keyset(
    stmt: Select,
    *,
    sort_column: InstrumentedAttribute,
    id_column: InstrumentedAttribute,
    cursor: str | None,
    limit: int,
    rank_column: InstrumentedAttribute | None = None,
    rank_decoder: Callable[[str], Any] | None = None,
) -> Select:
    """Applies ordering, the cursor predicate, and a limit of `limit + 1` --
    the extra row is how `build_page` detects whether another page exists
    without running a second COUNT query.

    `rank_column` adds a leading sort key ahead of the timestamp, for lists
    where recency is the tiebreaker rather than the point (findings sort by
    severity first). It must be a column Postgres can order meaningfully on
    its own: a native enum works, because Postgres orders enums by
    declaration order rather than alphabetically. `rank_decoder` turns the
    cursor's stored string back into a comparable value.
    """
    if rank_column is None:
        if cursor is not None:
            decoded = decode_cursor(cursor)
            stmt = stmt.where(tuple_(sort_column, id_column) < (decoded.sort_value, decoded.id))
        return stmt.order_by(sort_column.desc(), id_column.desc()).limit(limit + 1)

    if cursor is not None:
        decoded = decode_cursor(cursor)
        if decoded.rank is not None:
            try:
                rank_value = rank_decoder(decoded.rank) if rank_decoder else decoded.rank
            except (ValueError, KeyError, TypeError) as exc:
                raise HTTPException(status_code=422, detail=f"Malformed cursor: {exc}") from exc
            stmt = stmt.where(tuple_(rank_column, sort_column, id_column) < (rank_value, decoded.sort_value, decoded.id))
        else:
            # A cursor from the unranked ordering: fall back to its own predicate
            # rather than rejecting a client that is mid-pagination.
            stmt = stmt.where(tuple_(sort_column, id_column) < (decoded.sort_value, decoded.id))
    return stmt.order_by(rank_column.desc(), sort_column.desc(), id_column.desc()).limit(limit + 1)


def build_page(
    rows: list[Any],
    *,
    limit: int,
    sort_attr: str,
    serializer,
    rank_attr: str | None = None,
) -> dict:
    """Trims the sentinel row fetched by `apply_keyset` and builds the
    envelope. `next_cursor` is null on the last page. Pass the same
    `rank_attr` whenever `apply_keyset` was given a `rank_column`."""
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        rank = None
        if rank_attr is not None:
            raw = getattr(last, rank_attr)
            rank = raw.value if isinstance(raw, enum.Enum) else str(raw)
        next_cursor = encode_cursor(getattr(last, sort_attr), last.id, rank)
    return {"items": [serializer(r) for r in page], "next_cursor": next_cursor}
