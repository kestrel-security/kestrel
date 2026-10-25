# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-scoped LLM credentials for policy AI drafts.

API keys are envelope-encrypted like webhook signing secrets (ADR-0004).
Plaintext is accepted only on write — never returned again.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin

PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"
LLM_PROVIDERS = frozenset({PROVIDER_OPENAI, PROVIDER_ANTHROPIC})

DEFAULT_MODELS = {
    PROVIDER_OPENAI: "gpt-4o-mini",
    PROVIDER_ANTHROPIC: "claude-sonnet-5-5",
}

DEFAULT_BASE_URLS = {
    PROVIDER_OPENAI: "https://api.openai.com/v1",
    PROVIDER_ANTHROPIC: "https://api.anthropic.com",
}


class OrgLlmSettings(Base, TenantMixin, TimestampMixin):
    """One optional LLM config row per organization."""

    __tablename__ = "org_llm_settings"
    __table_args__ = (UniqueConstraint("org_id", name="uq_org_llm_settings_org_id"),)

    # Per-org settings go with the organization (the migration declared the cascade).
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default=PROVIDER_OPENAI)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_key_version: Mapped[int] = mapped_column(nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
