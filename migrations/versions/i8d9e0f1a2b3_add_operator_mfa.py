# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add TOTP multi-factor authentication for operators.

Operators gain an encrypted TOTP secret, its enrolment time, and the last
accepted time step (replay protection); single-use recovery codes are stored
hashed in their own table. Sessions record whether they are fully verified,
waiting for the second factor ("challenge"), or limited to enrolment
("enroll"). Organizations can require MFA for every operator.

Revision ID: i8d9e0f1a2b3
Revises: h7c8d9e0f1a2
Create Date: 2026-10-07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "i8d9e0f1a2b3"
down_revision: Union[str, None] = "h7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("operators", sa.Column("mfa_secret_ciphertext", sa.LargeBinary(), nullable=True))
    op.add_column("operators", sa.Column("mfa_secret_nonce", sa.LargeBinary(), nullable=True))
    op.add_column("operators", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operators", sa.Column("mfa_last_used_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "operator_sessions",
        sa.Column("mfa_state", sa.String(length=16), nullable=False, server_default="verified"),
    )
    op.add_column(
        "operator_sessions",
        sa.Column("mfa_failed_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("organizations", sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "operator_mfa_recovery_codes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_operator_mfa_recovery_codes_operator_id"), "operator_mfa_recovery_codes", ["operator_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_operator_mfa_recovery_codes_operator_id"), table_name="operator_mfa_recovery_codes")
    op.drop_table("operator_mfa_recovery_codes")
    op.drop_column("organizations", "require_mfa")
    op.drop_column("operator_sessions", "mfa_failed_attempts")
    op.drop_column("operator_sessions", "mfa_state")
    op.drop_column("operators", "mfa_last_used_step")
    op.drop_column("operators", "mfa_enabled_at")
    op.drop_column("operators", "mfa_secret_nonce")
    op.drop_column("operators", "mfa_secret_ciphertext")
