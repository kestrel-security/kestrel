# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add subject_type / subject_id to tenant_settings.

Per-repository, per-workspace, and per-policy settings need to attach to the
entity they govern rather than floating at the org. Both columns are nullable:
an existing tenant-wide setting keeps NULL and behaves exactly as before.

Revision ID: c1d2e3f4a5b6
Revises: b9c0d1e2f3a4
Create Date: 2026-08-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c1d2e3f4a5b6"
down_revision: Union[str, None] = "c0d1e2f3a4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tenant_settings", sa.Column("subject_type", sa.String(), nullable=True))
    op.add_column("tenant_settings", sa.Column("subject_id", sa.UUID(), nullable=True))
    op.create_index(
        "ix_tenant_settings_subject",
        "tenant_settings",
        ["org_id", "subject_type", "subject_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_tenant_settings_subject", table_name="tenant_settings")
    op.drop_column("tenant_settings", "subject_id")
    op.drop_column("tenant_settings", "subject_type")
