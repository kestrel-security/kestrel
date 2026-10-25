# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Record the master key id on every stored secret; mark existing rows legacy.

Revision ID: k0f1a2b3c4d5
Revises: j9e0f1a2b3c4
Create Date: 2026-10-09

From 0.4.0 every ciphertext is bound to its (table, row, field) with AES-GCM
associated data and stamped with the id of the master key that wrote it.
Rows written before this migration carry no associated data, so they are
marked ``key_version = 0`` (legacy) and keep decrypting until
``kestrel secrets rotate`` re-encrypts them -- run it once after upgrading.

Pure SQL, so it is safe under ``alembic upgrade head --sql``.

Downgrade drops the new columns and restores ``connector_secrets.key_version``
to 1. Rows already re-encrypted with associated data are unreadable by
pre-0.4.0 code: restore from a backup taken before the upgrade if you need to
roll back after rotating.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "k0f1a2b3c4d5"
down_revision: Union[str, None] = "j9e0f1a2b3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables whose secret column is NOT NULL: every row has a ciphertext, so the
# version is NOT NULL too. The server default is dropped after the backfill so
# an insert that forgets the version fails loudly instead of becoming legacy.
_REQUIRED = (
    ("webhook_endpoints", "secret_key_version"),
    ("ticket_integrations", "secret_key_version"),
    ("org_llm_settings", "secret_key_version"),
)

# Tables whose secret column is nullable: the version is NULL exactly when
# there is no ciphertext, and 0 (legacy) for every existing ciphertext.
_OPTIONAL = (
    ("operators", "mfa_secret_key_version", "mfa_secret_ciphertext"),
    ("org_smtp_settings", "password_key_version", "password_ciphertext"),
)


def upgrade() -> None:
    op.execute("UPDATE connector_secrets SET key_version = 0")
    for table, column in _REQUIRED:
        op.add_column(table, sa.Column(column, sa.Integer(), nullable=False, server_default="0"))
        op.alter_column(table, column, server_default=None)
    for table, column, ciphertext in _OPTIONAL:
        op.add_column(table, sa.Column(column, sa.Integer(), nullable=True))
        op.execute(f"UPDATE {table} SET {column} = 0 WHERE {ciphertext} IS NOT NULL")


def downgrade() -> None:
    for table, column, _ciphertext in reversed(_OPTIONAL):
        op.drop_column(table, column)
    for table, column in reversed(_REQUIRED):
        op.drop_column(table, column)
    op.execute("UPDATE connector_secrets SET key_version = 1")
