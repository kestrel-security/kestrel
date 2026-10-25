# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add system to the policy_source enum.

Additive only: appends a value for org-scoped system policies used by
toxic-combination reconciliation. Existing pack/custom rows are unchanged.

Downgrade is intentionally a no-op — Postgres cannot drop enum values in place.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-07-23
"""

from alembic import op

revision = "e6f7a8b9c0d1"
down_revision = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE policy_source ADD VALUE IF NOT EXISTS 'system'")


def downgrade() -> None:
    pass
