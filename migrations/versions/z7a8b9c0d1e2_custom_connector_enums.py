# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add api_key auth_method and custom resource_type.

Revision ID: z7a8b9c0d1e2
Revises: y6z7a8b9c0d1
Create Date: 2026-08-21
"""

from typing import Sequence, Union

from alembic import op

revision: str = "z7a8b9c0d1e2"
down_revision: Union[str, None] = "y6z7a8b9c0d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE auth_method ADD VALUE IF NOT EXISTS 'api_key'")
    op.execute("ALTER TYPE resource_type ADD VALUE IF NOT EXISTS 'custom'")


def downgrade() -> None:
    pass
