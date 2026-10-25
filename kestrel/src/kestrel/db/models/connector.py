# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy import false as sa_false
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class ConnectorSource(str, enum.Enum):
    BUILTIN = "builtin"
    COMMUNITY = "community"
    CUSTOM = "custom"


class AuthMethod(str, enum.Enum):
    PAT = "pat"
    OAUTH = "oauth"
    GITHUB_APP = "github_app"
    API_KEY = "api_key"


class SyncMode(str, enum.Enum):
    FIXTURES = "fixtures"
    LIVE = "live"


class ConnectorRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_FAILURE = "partial_failure"
    FAILED = "failed"


class ConnectorRunTrigger(str, enum.Enum):
    SCHEDULE = "schedule"
    MANUAL = "manual"
    API = "api"


class Connector(Base, TimestampMixin):
    """Registry of installed connector *code* (discovered via entry points),
    not per-org configuration -- see connectors/sdk/registry.py."""

    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, nullable=False)
    supported_object_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source: Mapped[ConnectorSource] = mapped_column(enum_column(ConnectorSource, name="connector_source"), nullable=False)


class ConnectorInstance(Base, TenantMixin, TimestampMixin):
    """Binds a connector to an application instance with config. Secrets are
    stored separately in ConnectorSecret, never inline here."""

    __tablename__ = "connector_instances"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connectors.id"), nullable=False)
    application_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_instances.id"), nullable=False
    )
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    auth_method: Mapped[AuthMethod] = mapped_column(enum_column(AuthMethod, name="auth_method"), nullable=False)
    sync_mode: Mapped[SyncMode] = mapped_column(
        enum_column(SyncMode, name="sync_mode"), default=SyncMode.FIXTURES, nullable=False
    )
    schedule_cron: Mapped[str | None] = mapped_column(String, nullable=True)


class ConnectorSecret(Base, TimestampMixin):
    """Ciphertext-only storage for connector credentials (see ADR-0004:
    envelope encryption via kestrel.secrets.crypto.KeyProvider)."""

    __tablename__ = "connector_secrets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_instances.id"), nullable=False, index=True
    )
    field_name: Mapped[str] = mapped_column(String, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Id of the master key that wrote this row (``kestrel.secrets.crypto.key_id``); 0 = legacy, no associated data.
    key_version: Mapped[int] = mapped_column(nullable=False)


class ConnectorRun(Base, TenantMixin):
    __tablename__ = "connector_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_instances.id"), nullable=False, index=True
    )
    status: Mapped[ConnectorRunStatus] = mapped_column(
        enum_column(ConnectorRunStatus, name="connector_run_status"), default=ConnectorRunStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    object_counts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Families this run could not read, mapped to a coarse failure class
    # ("permission", "rate_limit", "not_configured", …). Structured rather than
    # folded into `error_summary`, so "we could not read your audit log" is not
    # in the same field as a stack trace and the UI can act on it.
    skipped_object_types: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    error_summary: Mapped[str | None] = mapped_column(String, nullable=True)
    triggered_by: Mapped[ConnectorRunTrigger] = mapped_column(
        enum_column(ConnectorRunTrigger, name="connector_run_trigger"), default=ConnectorRunTrigger.MANUAL, nullable=False
    )
    # True for a cursored run that deliberately collected only some object
    # types. Such a run is a SUCCESS -- it read everything it meant
    # to -- but it is not a full inventory, so it must not count as the
    # Changes baseline and must not stand in for a full sync when judging
    # whether a connector is stale.
    is_incremental: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Set when the run's sync commits and cleared once an evaluation covering
    # it succeeds. Still set means policy evaluation for this data never
    # finished (it failed, or the process died), so the next sync in the org
    # evaluates in full instead of deciding there is nothing new.
    evaluation_pending: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())


class ConnectorCursor(Base, TenantMixin):
    """High-water mark for one incrementally-collectable object type.

    ``Collector.collect(since=)`` has been in the protocol since the SDK
    shipped, and Okta and Slack both plumb it -- but nothing ever
    passed it, because there was nowhere to persist where the last run got to.
    Every sync re-read the provider's full default audit window.

    The value is a string rather than a timestamp so an opaque provider cursor
    (GitHub's ascending audit-log ``after`` token) fits the same row as a
    time-based watermark. ``advanced_at`` is when Kestrel last moved it, which
    is not the same as the watermark itself and is what operators need when a
    poll appears stuck.
    """

    __tablename__ = "connector_cursors"
    __table_args__ = (UniqueConstraint("connector_instance_id", "object_type"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_instances.id"), nullable=False, index=True
    )
    object_type: Mapped[str] = mapped_column(String, nullable=False)
    cursor: Mapped[str] = mapped_column(String, nullable=False)
    advanced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
