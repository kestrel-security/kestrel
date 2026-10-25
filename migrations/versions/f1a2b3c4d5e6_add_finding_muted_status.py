# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add muted finding status + mute columns.

Additive: appends ``muted`` to ``finding_status`` and adds
``muted_until`` / ``mute_reason`` on findings. Downgrade drops columns
but cannot remove the enum value (Postgres limitation).

Revision ID: f1a2b3c4d5e6
Revises: e0f1a2b3c4d5
Create Date: 2026-07-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, None] = "e0f1a2b3c4d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE finding_status ADD VALUE IF NOT EXISTS 'muted'")
    op.add_column(
        "findings",
        sa.Column("muted_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("mute_reason", sa.String(), nullable=True),
    )
    op.create_index(
        op.f("ix_findings_muted_until"),
        "findings",
        ["muted_until"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_muted_until"), table_name="findings")
    op.drop_column("findings", "mute_reason")
    op.drop_column("findings", "muted_until")
