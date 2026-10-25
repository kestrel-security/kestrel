# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add cisa to the compliance_framework enum

Additive only: appends a value to an existing Postgres enum. Existing rows
and queries are unaffected, and nothing is renamed or removed.

Needed by the saas-posture policy pack, which maps detections to
CISA Secure Cloud Business Applications (SCuBA)–style control IDs.

Downgrade is intentionally a no-op. Postgres cannot drop a value from an
enum type in place; reversing this would mean recreating the type and
rewriting every dependent column, which is a destructive operation to run
automatically on a downgrade path.

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
Create Date: 2026-07-22
"""

from alembic import op

revision = "c8d9e0f1a2b3"
down_revision = "b7c8d9e0f1a2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS keeps re-running the migration safe.
    op.execute("ALTER TYPE compliance_framework ADD VALUE IF NOT EXISTS 'cisa'")


def downgrade() -> None:
    pass
