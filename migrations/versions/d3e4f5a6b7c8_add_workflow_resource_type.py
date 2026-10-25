# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add workflow resource_type.

The Slack normalizer emits Workflow Builder workflows as resources, but the
enum never gained the value, so every Slack sync that collected one failed.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-10-03
"""

from typing import Sequence, Union

from alembic import op

revision: str = "d3e4f5a6b7c8"
down_revision: Union[str, None] = "c2d3e4f5a6b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE resource_type ADD VALUE IF NOT EXISTS 'workflow'")


def downgrade() -> None:
    # Postgres cannot drop an enum value; leaving it is harmless.
    pass
