# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add application to finding_subject_type.

Additive: appends ``application`` so RESOURCE_TYPE=application policies can
open findings with subject_type matching dataload ``_subject_type``.
Downgrade cannot remove the enum value (Postgres limitation).

Revision ID: q8r9s0t1u2v3
Revises: p7q8r9s0t1u2
Create Date: 2026-07-30
"""

from typing import Sequence, Union

from alembic import op

revision: str = "q8r9s0t1u2v3"
down_revision: Union[str, None] = "p7q8r9s0t1u2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE finding_subject_type ADD VALUE IF NOT EXISTS 'application'")


def downgrade() -> None:
    # Postgres cannot remove enum values safely; leave finding_subject_type
    # 'application' in place on downgrade.
    pass
