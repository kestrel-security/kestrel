# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum

from sqlalchemy import Boolean, Index, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin, enum_column


class ResourceType(str, enum.Enum):
    REPOSITORY = "repository"
    CHANNEL = "channel"
    DRIVE_FILE = "drive_file"
    # A Google Workspace shared drive is a container that carries its own
    # membership and permissions, not a file inside one -- modeling it as
    # DRIVE_FILE would mislead policies filtering on resource type.
    SHARED_DRIVE = "shared_drive"
    # SharePoint site (Microsoft 365) — container with its own permissions.
    SHAREPOINT_SITE = "sharepoint_site"
    # Managed endpoint (mobile, ChromeOS, Okta device, etc.). Posture
    # attributes live as subject-scoped settings on the device resource.
    DEVICE = "device"
    # Slack workflow (Workflow Builder). Governance attributes -- trigger,
    # external steps, publishing -- live in `config`.
    WORKFLOW = "workflow"
    # Generic object from a custom / internal application.
    # Provider subtype stays in attributes / raw_source.
    CUSTOM = "custom"


class ResourceVisibility(str, enum.Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"


class Resource(Base, ProvenanceMixin):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("application_instance_id", "provider_object_id"),
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_resources_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
    )

    resource_type: Mapped[ResourceType] = mapped_column(enum_column(ResourceType, name="resource_type"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    visibility: Mapped[ResourceVisibility | None] = mapped_column(
        enum_column(ResourceVisibility, name="resource_visibility"), nullable=True
    )
    is_sensitive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Normalized posture attributes (branch protection, secret scanning, etc.)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
