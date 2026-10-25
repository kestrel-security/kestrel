# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Track whether a sync's policy evaluation is still owed.

A sync commits before evaluating policies. If evaluation then fails, the next
audit-log poll used to see nothing new and skip evaluation, leaving that
change unevaluated until the next full sync. ``evaluation_pending`` records
the debt so the next run evaluates in full.

Revision ID: h7c8d9e0f1a2
Revises: g6b7c8d9e0f1
Create Date: 2026-10-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "h7c8d9e0f1a2"
down_revision: Union[str, None] = "g6b7c8d9e0f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "connector_runs",
        sa.Column("evaluation_pending", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("connector_runs", "evaluation_pending")
