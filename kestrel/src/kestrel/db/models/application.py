# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class ApplicationType(str, enum.Enum):
    GITHUB = "github"
    GOOGLE_WORKSPACE = "google_workspace"
    SLACK = "slack"
    OKTA = "okta"
    MICROSOFT_365 = "microsoft_365"
    CUSTOM = "custom"


class ApplicationInstanceStatus(str, enum.Enum):
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class Application(Base, TenantMixin, TimestampMixin):
    """Catalog entry for an application *type* (e.g. "GitHub" as a concept),
    distinct from a specific connected instance of it."""

    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    application_type: Mapped[ApplicationType] = mapped_column(
        enum_column(ApplicationType, name="application_type"), nullable=False
    )
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)


class ApplicationInstance(Base, TenantMixin, TimestampMixin):
    """A configured, connected instance of an application for this org
    (e.g. "Acme Corp's GitHub org")."""

    __tablename__ = "application_instances"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), nullable=False)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    external_tenant_ref: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[ApplicationInstanceStatus] = mapped_column(
        enum_column(ApplicationInstanceStatus, name="application_instance_status"),
        default=ApplicationInstanceStatus.ACTIVE,
        nullable=False,
    )
