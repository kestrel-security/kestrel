# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add identities.last_active_source.

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
Create Date: 2026-09-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f4a5b6c7d8e9"
down_revision: Union[str, None] = "e3f4a5b6c7d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("identities", sa.Column("last_active_source", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("identities", "last_active_source")
