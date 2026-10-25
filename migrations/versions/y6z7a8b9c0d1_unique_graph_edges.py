# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unique graph edges by endpoints and access_path.

Revision ID: y6z7a8b9c0d1
Revises: x5y6z7a8b9c0
Create Date: 2026-08-19

A person can hold the same role both directly and via a group. Those are two
edges (access_path differs), not duplicates. Uniqueness is therefore
(org, source, target, edge_type, access_path).
"""

from typing import Sequence, Union

from alembic import op

revision: str = "y6z7a8b9c0d1"
down_revision: Union[str, None] = "x5y6z7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM graph_edges a
        USING graph_edges b
        WHERE a.org_id = b.org_id
          AND a.source_node_id = b.source_node_id
          AND a.target_node_id = b.target_node_id
          AND a.edge_type = b.edge_type
          AND a.access_path IS NOT DISTINCT FROM b.access_path
          AND a.id > b.id
        """
    )
    op.create_unique_constraint(
        "uq_graph_edges_endpoints",
        "graph_edges",
        ["org_id", "source_node_id", "target_node_id", "edge_type", "access_path"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_graph_edges_endpoints", "graph_edges", type_="unique")
