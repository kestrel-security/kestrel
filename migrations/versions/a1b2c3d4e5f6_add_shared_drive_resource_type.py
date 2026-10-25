# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add shared_drive to the resource_type enum

Additive only: appends a value to an existing Postgres enum. Existing rows
and queries are unaffected, and nothing is renamed or removed.

Needed by the Google Workspace connector, whose shared drives are
permission-bearing containers rather than files -- see ResourceType.

Downgrade is intentionally a no-op. Postgres cannot drop a value from an
enum type in place; reversing this would mean recreating the type and
rewriting every dependent column, which is a destructive operation to run
automatically on a downgrade path.

Revision ID: a1b2c3d4e5f6
Revises: 52c6a9b4e853
Create Date: 2026-07-22
"""

from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "52c6a9b4e853"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS keeps re-running the migration safe.
    op.execute("ALTER TYPE resource_type ADD VALUE IF NOT EXISTS 'shared_drive'")


def downgrade() -> None:
    pass
