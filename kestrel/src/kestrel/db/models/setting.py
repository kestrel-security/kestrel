# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""SaaS configuration / security posture settings.

One row per normalized setting key collected from a connector (2FA
requirement, default repo permission, sharing controls, …). Drift is tracked
via ProvenanceMixin + Event change detection on upsert.

Most settings are tenant-wide, but not all posture lives at the tenant. A
GitHub branch protection rule belongs to one repository, a Slack setting to one
workspace, an Okta policy rule to one policy. Those carry
``subject_type``/``subject_id`` so the setting attaches to the node
it actually governs -- via an ``applies_to`` graph edge, and as a `settings`
list on that subject's policy row -- rather than floating at the org with the
repo name buried in its key. The table name stays ``tenant_settings``; renaming
it would be a migration with no product value.
"""

import uuid

from sqlalchemy import Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin


class TenantSetting(Base, ProvenanceMixin):
    __tablename__ = "tenant_settings"
    __table_args__ = (
        UniqueConstraint("application_instance_id", "provider_object_id"),
        Index("ix_tenant_settings_subject", "org_id", "subject_type", "subject_id"),
    )

    key: Mapped[str] = mapped_column(String, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    # Boolean / string / number / object stored as JSON so the legacy policy DSL can compare
    # scalars directly (`setting.value == false`).
    value: Mapped[object] = mapped_column(JSONB(none_as_null=False), nullable=False)
    value_type: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)

    # Null for a tenant-wide setting. Otherwise the entity this setting governs:
    # `subject_type` is a normalized kind ("resource", "group", "oauth_application"),
    # `subject_id` the Kestrel id of that row. No FK -- the target is polymorphic,
    # the same way `events.entity_id` is.
    subject_type: Mapped[str | None] = mapped_column(String, nullable=True)
    subject_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
