# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column
from kestrel.db.models.policy import Severity


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    EXCEPTION = "exception"
    MUTED = "muted"


class FindingSubjectType(str, enum.Enum):
    IDENTITY = "identity"
    RESOURCE = "resource"
    OAUTH_APPLICATION = "oauth_application"
    SETTING = "setting"
    EVENT = "event"
    APPLICATION = "application"


class Finding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_versions.id"), nullable=False, index=True
    )
    policy_evaluation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_evaluations.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, name="severity"), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        enum_column(FindingStatus, name="finding_status"), default=FindingStatus.OPEN, nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    subject_type: Mapped[FindingSubjectType] = mapped_column(
        enum_column(FindingSubjectType, name="finding_subject_type"), nullable=False
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assigned_to_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Temporary deferral; required when status=muted, cleared on unmute.
    muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    mute_reason: Mapped[str | None] = mapped_column(String, nullable=True)


class FindingEvidence(Base):
    """One row per evidence field selected in a policy's `evidence {}` block
    -- an auditable list rather than one opaque JSON blob."""

    __tablename__ = "finding_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    # none_as_null=False: evidence values are frequently absent (e.g. GitHub
    # doesn't expose member emails), and that's a meaningful JSON `null`
    # evidence value, not the absence of a row -- without this flag,
    # assigning Python None here would attempt a SQL NULL and violate
    # `nullable=False`.
    value: Mapped[dict] = mapped_column(JSONB(none_as_null=False), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Exception_(Base, TenantMixin):
    """Named with a trailing underscore to avoid shadowing the builtin
    `Exception`. Either scoped to a single finding or org-wide for a policy."""

    __tablename__ = "exceptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=True)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
