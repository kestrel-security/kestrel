# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TimestampMixin, enum_column


class ComplianceFramework(str, enum.Enum):
    SOC2 = "soc2"
    CIS = "cis"
    NIST_CSF = "nist_csf"
    CISA = "cisa"
    CUSTOM = "custom"


class MappingSource(str, enum.Enum):
    PACK_DEFAULT = "pack_default"
    USER_OVERRIDE = "user_override"


class ComplianceControl(Base, TimestampMixin):
    """org_id is nullable here (unlike TenantMixin's non-null default): a null
    org_id is a built-in framework control shared across all orgs; non-null is
    an org's custom control."""

    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("org_id", "framework", "control_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    framework: Mapped[ComplianceFramework] = mapped_column(
        enum_column(ComplianceFramework, name="compliance_framework"), nullable=False
    )
    control_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)


class PolicyControlMapping(Base):
    __tablename__ = "policy_control_mappings"
    __table_args__ = (UniqueConstraint("policy_id", "compliance_control_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=False, index=True)
    compliance_control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False, index=True
    )
    source: Mapped[MappingSource] = mapped_column(enum_column(MappingSource, name="mapping_source"), nullable=False)
