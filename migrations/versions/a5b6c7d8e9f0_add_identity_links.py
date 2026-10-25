# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add identity_links: persisted cross-app identity correlation.

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
Create Date: 2026-09-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a5b6c7d8e9f0"
down_revision: Union[str, None] = "f4a5b6c7d8e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "identity_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column(
            "identity_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cluster_key", sa.String(), nullable=False),
        sa.Column("representative_identity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("match_kind", sa.String(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("application_types", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "identity_id", name="uq_identity_links_org_identity"),
    )
    op.create_index("ix_identity_links_org_id", "identity_links", ["org_id"])
    op.create_index("ix_identity_links_identity_id", "identity_links", ["identity_id"])
    op.create_index("ix_identity_links_cluster", "identity_links", ["org_id", "cluster_key"])


def downgrade() -> None:
    op.drop_index("ix_identity_links_cluster", table_name="identity_links")
    op.drop_index("ix_identity_links_identity_id", table_name="identity_links")
    op.drop_index("ix_identity_links_org_id", table_name="identity_links")
    op.drop_table("identity_links")
