# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add oauth_grants provenance columns for revocation detection.

Revision ID: u2v3w4x5y6z7
Revises: t1u2v3w4x5y6
Create Date: 2026-08-10
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "u2v3w4x5y6z7"
down_revision: Union[str, None] = "t1u2v3w4x5y6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "oauth_grants",
        sa.Column("source_connector_run_id", sa.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_oauth_grants_source_connector_run_id",
        "oauth_grants",
        "connector_runs",
        ["source_connector_run_id"],
        ["id"],
    )
    # Backfilled to now() so pre-existing grants aren't immediately reported as
    # revoked by the first sync after this migration.
    op.add_column(
        "oauth_grants",
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column(
        "oauth_grants",
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_oauth_grants_last_seen_at",
        "oauth_grants",
        ["org_id", "last_seen_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_oauth_grants_last_seen_at", table_name="oauth_grants")
    op.drop_column("oauth_grants", "last_seen_at")
    op.drop_column("oauth_grants", "first_seen_at")
    op.drop_constraint("fk_oauth_grants_source_connector_run_id", "oauth_grants", type_="foreignkey")
    op.drop_column("oauth_grants", "source_connector_run_id")
