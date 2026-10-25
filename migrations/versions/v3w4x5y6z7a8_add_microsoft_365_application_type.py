# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add microsoft_365 to application_type enum.

Revision ID: v3w4x5y6z7a8
Revises: u2v3w4x5y6z7
Create Date: 2026-08-11
"""

from typing import Sequence, Union

from alembic import op

revision: str = "v3w4x5y6z7a8"
down_revision: Union[str, None] = "u2v3w4x5y6z7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE application_type ADD VALUE IF NOT EXISTS 'microsoft_365'")


def downgrade() -> None:
    # PostgreSQL cannot easily remove enum values; leave microsoft_365 in place.
    pass
