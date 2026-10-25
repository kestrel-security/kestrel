# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-scoped dashboards, widgets, schedules, and export audit."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class DashboardVisibility(str, enum.Enum):
    ORG = "org"
    PRIVATE = "private"


class DashboardVizType(str, enum.Enum):
    KPI = "kpi"
    TABLE = "table"
    BAR = "bar"
    PIE = "pie"
    DONUT = "donut"
    LINE = "line"
    AREA = "area"
    LIST = "list"
    MARKDOWN = "markdown"
    # Built-in posture widgets that render from GET /dashboard overview
    PRESET = "preset"


class DashboardScheduleFormat(str, enum.Enum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


class Dashboard(Base, TenantMixin, TimestampMixin):
    """Named board under /dashboard (DEC-023)."""

    __tablename__ = "dashboards"
    __table_args__ = (UniqueConstraint("org_id", "slug"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    visibility: Mapped[DashboardVisibility] = mapped_column(
        enum_column(DashboardVisibility, name="dashboard_visibility"),
        default=DashboardVisibility.ORG,
        nullable=False,
    )
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    # Operator who pinned this board as their nav home (optional prefs also store pin).
    # Prefer operators.ui_preferences["dashboard_home_id"] for personal pin.


class DashboardWidget(Base, TenantMixin, TimestampMixin):
    """One widget on a dashboard grid."""

    __tablename__ = "dashboard_widgets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dashboard_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False, index=True
    )
    widget_key: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    viz_type: Mapped[DashboardVizType] = mapped_column(
        enum_column(DashboardVizType, name="dashboard_viz_type"), nullable=False
    )
    # Constrained metric DSL or {"preset": "open_by_severity"} for built-ins.
    query_spec: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Grid position: {x, y, w, h} on a 12-column grid.
    layout: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    refresh_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Optional markdown body when viz_type=markdown.
    body_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)


class DashboardSchedule(Base, TenantMixin, TimestampMixin):
    """Cron email (or future channel) for a dashboard snapshot."""

    __tablename__ = "dashboard_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dashboard_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cron: Mapped[str] = mapped_column(String(120), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    format: Mapped[DashboardScheduleFormat] = mapped_column(
        enum_column(DashboardScheduleFormat, name="dashboard_schedule_format"),
        default=DashboardScheduleFormat.PDF,
        nullable=False,
    )
    # List of operator UUID strings (org members only in v1).
    recipient_operator_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )


class DashboardExport(Base, TenantMixin, TimestampMixin):
    """Audit row for exports (PDF/JSON/HTML/CSV)."""

    __tablename__ = "dashboard_exports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dashboard_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False, index=True
    )
    operator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    byte_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
