# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add okta to discovered_application_source.

Revision ID: k2l3m4n5o6p7
Revises: j1k2l3m4n5o6
Create Date: 2026-07-30
"""

from typing import Sequence, Union

from alembic import op

revision: str = "k2l3m4n5o6p7"
down_revision: Union[str, None] = "j1k2l3m4n5o6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ADD VALUE cannot run inside a transaction on some Postgres versions;
    # Alembic's default transaction is fine for recent PG with IF NOT EXISTS.
    op.execute("ALTER TYPE discovered_application_source ADD VALUE IF NOT EXISTS 'okta'")


def downgrade() -> None:
    # Enum values cannot be removed safely without table rewrite; leave in place.
    pass
