# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add non_human access-review scope + item kinds.

Revision ID: m4n5o6p7q8r9
Revises: l3m4n5o6p7q8
Create Date: 2026-07-30
"""

from typing import Sequence, Union

from alembic import op

revision: str = "m4n5o6p7q8r9"
down_revision: Union[str, None] = "l3m4n5o6p7q8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE access_review_scope ADD VALUE IF NOT EXISTS 'non_human'")
    op.execute(
        "ALTER TYPE access_review_item_kind ADD VALUE IF NOT EXISTS 'non_human_identity'"
    )
    op.execute(
        "ALTER TYPE access_review_item_kind ADD VALUE IF NOT EXISTS 'oauth_application'"
    )


def downgrade() -> None:
    # Postgres cannot remove enum values safely; leave values in place.
    pass
