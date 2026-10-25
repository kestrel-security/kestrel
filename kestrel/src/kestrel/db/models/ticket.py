# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Outbound ticketing integrations + finding ticket refs.

API tokens are envelope-encrypted like webhook signing secrets (ADR-0004).
Plaintext is accepted only on create/rotate — never returned again.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin

# Built-in provider ids (entry-point providers may add more).
GITHUB_ISSUES = "github_issues"
JIRA_CLOUD = "jira_cloud"
BUILTIN_TICKET_PROVIDERS = frozenset({GITHUB_ISSUES, JIRA_CLOUD})


class TicketIntegration(Base, TenantMixin, TimestampMixin):
    """Org-configured ticket tracker (GitHub Issues, Jira Cloud, …)."""

    __tablename__ = "ticket_integrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Provider-specific non-secret config (repo, project_key, base_url, …).
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_key_version: Mapped[int] = mapped_column(nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class FindingTicket(Base, TenantMixin):
    """Record of a ticket created from a finding (external URL + ref)."""

    __tablename__ = "finding_tickets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ticket_integration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket_integrations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
