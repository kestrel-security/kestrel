# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Typed helpers for graph query results, so callers (API routers, the
graph UI serializer) don't work with raw row mappings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any


@dataclass
class GraphNodeRef:
    id: uuid.UUID
    node_type: str
    object_id: uuid.UUID
    label: str
    properties: dict[str, Any]

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> GraphNodeRef:
        raw_type = row["node_type"]
        node_type = raw_type.value if hasattr(raw_type, "value") else str(raw_type)
        return cls(
            id=row["id"],
            node_type=node_type,
            object_id=row["object_id"],
            label=row["label"],
            properties=row["properties"] or {},
        )
