# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator rules that classify accounts into a ``worker_type``.

Connectors can only say what their provider knows: Okta has a user type, Slack
has guest tiers, Google Workspace has nothing but an org unit path. A rule
turns the facts an organization actually encodes ("everyone under
``/Contractors``", "the ``contractors`` group", "any ``@vendor.example``
address") into the shared vocabulary, so a cross-application policy can ask for
contractors and get the same answer in every application.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin

#: What a rule matches on. ``match_value`` is interpreted per kind: a domain
#: (equal or a subdomain), an org-unit path prefix on a path boundary, a
#: case-insensitive shell glob over group names or the provider's raw user
#: type, or an application type.
MATCH_KINDS: tuple[str, ...] = (
    "email_domain",
    "org_unit_path_prefix",
    "group_name",
    "user_type",
    "application_type",
)


class OrgIdentityClassificationRule(Base, TenantMixin, TimestampMixin):
    __tablename__ = "org_identity_classification_rules"
    __table_args__ = (Index("ix_org_identity_classification_rules_priority", "org_id", "priority"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Lower wins. Rules are stored as an ordered list, so this is the position.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    worker_type: Mapped[str] = mapped_column(String(32), nullable=False)
    match_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    match_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Optional scope: only accounts in this application type are considered.
    application_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "priority": self.priority,
            "is_enabled": self.is_enabled,
            "worker_type": self.worker_type,
            "match_kind": self.match_kind,
            "match_value": self.match_value,
            "application_type": self.application_type,
            "label": self.label,
        }
