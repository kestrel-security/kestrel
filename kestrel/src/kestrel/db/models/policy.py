# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicySource(str, enum.Enum):
    PACK = "pack"
    CUSTOM = "custom"
    # Org-scoped derived rules (e.g. toxic combinations) — not legacy-policy-DSL-evaluated.
    SYSTEM = "system"


class PolicyEvaluationStatus(str, enum.Enum):
    SUCCESS = "success"
    ERROR = "error"


class Policy(Base, TenantMixin, TimestampMixin):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("org_id", "slug"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    # Deliberately not a DB foreign key: policy_versions.policy_id already
    # points back to policies.id, and a real FK here would create a circular
    # dependency between the two tables. Application code is responsible for
    # keeping this in sync with an actual PolicyVersion row.
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source: Mapped[PolicySource] = mapped_column(enum_column(PolicySource, name="policy_source"), nullable=False)
    pack_name: Mapped[str | None] = mapped_column(String, nullable=True)
    # Custom-policy Workbench fixtures only. Pack fixtures stay on disk.
    fixtures: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class PolicyVersion(Base, TimestampMixin):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_text: Mapped[str] = mapped_column(String, nullable=False)
    ast_cache: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, name="severity"), nullable=False)
    remediation: Mapped[str | None] = mapped_column(String, nullable=True)
    compliance_mappings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)


class PolicyEvaluation(Base, TenantMixin):
    __tablename__ = "policy_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_versions.id"), nullable=False, index=True
    )
    connector_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[PolicyEvaluationStatus] = mapped_column(
        enum_column(PolicyEvaluationStatus, name="policy_evaluation_status"), nullable=False
    )
    matched_object_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
