# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Constrained metric DSL for dashboard widgets.

Allowlisted JSON only — no raw SQL, no raw_source projection.
Every query injects org_id and enforces result caps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import DateTime, func, select
from sqlalchemy.orm import Session

from kestrel.connectors.health import classify_sync_health
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.policy import Severity
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting

EntityName = Literal["finding", "connector", "posture_trend"]
FilterOp = Literal["eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte", "is_null", "not_null"]
MetricFn = Literal["count", "count_distinct"]

MAX_LIMIT = 100
DEFAULT_LIMIT = 20

FINDING_FIELDS = frozenset(
    {
        "status",
        "severity",
        "subject_type",
        "assigned_to_operator_id",
        "application_type",
        "application_instance_id",
        "first_seen_at",
        "last_seen_at",
        "opened_at",  # alias for first_seen_at
    }
)
CONNECTOR_FIELDS = frozenset({"health", "sync_mode"})
CONNECTOR_FILTER_OPS = frozenset({"eq", "neq", "in", "not_in"})
POSTURE_TREND_MAX_DAYS = 365
GROUPABLE_FINDING = frozenset({"status", "severity", "subject_type"})
GROUPABLE_CONNECTOR = frozenset({"health", "sync_mode"})


class QueryFilter(BaseModel):
    field: str
    op: FilterOp = "eq"
    value: Any = None


class QueryMetric(BaseModel):
    fn: MetricFn = "count"
    field: str = "*"


class QueryOrder(BaseModel):
    field: str
    dir: Literal["asc", "desc"] = "desc"


class QueryTimeRange(BaseModel):
    field: str = "first_seen_at"
    last: str | None = None  # e.g. "7d", "30d"
    since: datetime | None = None
    until: datetime | None = None


class QuerySpec(BaseModel):
    """Allowlisted aggregate query. Preset widgets use ``preset`` instead."""

    preset: str | None = None
    entity: EntityName | None = None
    filters: list[QueryFilter] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=list)
    metric: QueryMetric = Field(default_factory=QueryMetric)
    order_by: list[QueryOrder] = Field(default_factory=list)
    limit: int = DEFAULT_LIMIT
    time_range: QueryTimeRange | None = None

    @field_validator("limit")
    @classmethod
    def _cap_limit(cls, v: int) -> int:
        if v < 1:
            raise ValueError("limit must be >= 1")
        return min(v, MAX_LIMIT)

    @model_validator(mode="after")
    def _entity_or_preset(self) -> QuerySpec:
        if self.preset:
            return self
        if not self.entity:
            raise ValueError("entity is required when preset is unset")
        return self


def parse_query_spec(raw: dict[str, Any] | QuerySpec) -> QuerySpec:
    if isinstance(raw, QuerySpec):
        return raw
    return QuerySpec.model_validate(raw)


def _parse_last(last: str) -> timedelta:
    last = last.strip().lower()
    if last.endswith("d") and last[:-1].isdigit():
        return timedelta(days=int(last[:-1]))
    if last.endswith("h") and last[:-1].isdigit():
        return timedelta(hours=int(last[:-1]))
    raise ValueError(f"unsupported time_range.last: {last}")


def _finding_app_type_ids(db: Session, org_id: uuid.UUID, app_type: str) -> list[uuid.UUID]:
    try:
        at = ApplicationType(app_type)
    except ValueError as exc:
        raise ValueError(f"unknown application_type: {app_type}") from exc
    rows = db.scalars(
        select(ApplicationInstance.id)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(
            ApplicationInstance.org_id == org_id,
            Application.application_type == at,
        )
    ).all()
    return list(rows)


def _apply_finding_app_instance_filter(stmt, org_id: uuid.UUID, instance_ids: list[uuid.UUID]):
    if not instance_ids:
        return stmt.where(False)
    id_set = set(instance_ids)
    return stmt.where(
        Finding.subject_id.in_(
            select(Identity.id).where(
                Identity.org_id == org_id,
                Identity.application_instance_id.in_(id_set),
            )
        )
        | Finding.subject_id.in_(
            select(Resource.id).where(
                Resource.org_id == org_id,
                Resource.application_instance_id.in_(id_set),
            )
        )
        | Finding.subject_id.in_(
            select(OAuthApplication.id).where(
                OAuthApplication.org_id == org_id,
                OAuthApplication.application_instance_id.in_(id_set),
            )
        )
        | Finding.subject_id.in_(
            select(TenantSetting.id).where(
                TenantSetting.org_id == org_id,
                TenantSetting.application_instance_id.in_(id_set),
            )
        )
        | Finding.subject_id.in_(
            select(ApplicationInstance.id).where(
                ApplicationInstance.org_id == org_id,
                ApplicationInstance.id.in_(id_set),
            )
        )
    )


def execute_query(
    db: Session,
    *,
    org_id: uuid.UUID,
    spec: QuerySpec | dict[str, Any],
    viewer_operator_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Run an allowlisted aggregate. Returns series/rows for charts."""
    parsed = parse_query_spec(spec)
    if parsed.preset:
        return {
            "kind": "preset",
            "preset": parsed.preset,
            "series": [],
            "rows": [],
            "total": 0,
            "drilldown": {},
        }

    assert parsed.entity is not None
    if parsed.entity == "finding":
        return _execute_finding(db, org_id=org_id, spec=parsed, viewer_operator_id=viewer_operator_id)
    if parsed.entity == "connector":
        return _execute_connector(db, org_id=org_id, spec=parsed)
    if parsed.entity == "posture_trend":
        return _execute_posture_trend(db, org_id=org_id, spec=parsed)
    raise ValueError(f"unsupported entity: {parsed.entity}")


def _drilldown_from_spec(spec: QuerySpec) -> dict[str, Any]:
    """Findings list query params derived from filters."""
    params: dict[str, Any] = {}
    for f in spec.filters:
        if f.field == "status" and f.op == "eq":
            params["status"] = f.value
        elif f.field == "severity" and f.op in ("eq", "in"):
            params["severity"] = f.value if f.op == "eq" else ",".join(f.value)
        elif f.field == "application_instance_id" and f.op == "eq":
            params["application_instance_id"] = str(f.value)
    return params


def _execute_finding(
    db: Session,
    *,
    org_id: uuid.UUID,
    spec: QuerySpec,
    viewer_operator_id: uuid.UUID | None,
) -> dict[str, Any]:
    for g in spec.group_by:
        if g not in GROUPABLE_FINDING:
            raise ValueError(f"group_by not allowed for finding: {g}")
    for f in spec.filters:
        if f.field not in FINDING_FIELDS:
            raise ValueError(f"filter field not allowed: {f.field}")

    stmt = select(Finding.id).where(Finding.org_id == org_id)

    for f in spec.filters:
        if f.field == "application_type":
            if f.op != "eq" or not isinstance(f.value, str):
                raise ValueError("application_type filter requires op=eq and string value")
            ids = _finding_app_type_ids(db, org_id, f.value)
            stmt = _apply_finding_app_instance_filter(stmt, org_id, ids)
            continue
        if f.field == "application_instance_id":
            try:
                iid = uuid.UUID(str(f.value))
            except ValueError as exc:
                raise ValueError("invalid application_instance_id") from exc
            stmt = _apply_finding_app_instance_filter(stmt, org_id, [iid])
            continue
        if f.field == "opened_at":
            f = QueryFilter(field="first_seen_at", op=f.op, value=f.value)
        if f.field == "assigned_to_operator_id" and f.op == "eq" and f.value == "me":
            if viewer_operator_id is None:
                raise ValueError("viewer required for assigned_to_operator_id=me")
            stmt = stmt.where(Finding.assigned_to_operator_id == viewer_operator_id)
            continue
        if f.field == "assigned_to_operator_id" and f.op == "is_null":
            stmt = stmt.where(Finding.assigned_to_operator_id.is_(None))
            continue
        col = getattr(Finding, f.field, None)
        if col is None:
            raise ValueError(f"unknown field: {f.field}")
        stmt = _apply_op(stmt, col, f)

    if spec.time_range:
        tr = spec.time_range
        field_name = "first_seen_at" if tr.field in ("opened_at", "first_seen_at") else tr.field
        if field_name not in ("first_seen_at", "last_seen_at"):
            raise ValueError(f"time_range.field not allowed: {tr.field}")
        col = getattr(Finding, field_name)
        now = datetime.now(UTC)
        if tr.last:
            stmt = stmt.where(col >= now - _parse_last(tr.last))
        if tr.since:
            stmt = stmt.where(col >= tr.since)
        if tr.until:
            stmt = stmt.where(col <= tr.until)

    if not spec.group_by:
        # KPI-style count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = int(db.scalar(count_stmt) or 0)
        return {
            "kind": "kpi",
            "entity": "finding",
            "series": [{"name": "count", "value": total}],
            "rows": [{"label": "count", "value": total}],
            "total": total,
            "drilldown": _drilldown_from_spec(spec),
        }

    group_cols = [getattr(Finding, g) for g in spec.group_by]
    agg = func.count().label("count")
    id_subq = stmt.subquery()
    grouped = select(*group_cols, agg).where(Finding.id.in_(select(id_subq.c.id))).group_by(*group_cols)
    if spec.order_by:
        for o in spec.order_by:
            if o.field == "count":
                grouped = grouped.order_by(agg.desc() if o.dir == "desc" else agg.asc())
            elif o.field in spec.group_by:
                c = getattr(Finding, o.field)
                grouped = grouped.order_by(c.desc() if o.dir == "desc" else c.asc())
    else:
        grouped = grouped.order_by(agg.desc())
    grouped = grouped.limit(spec.limit)

    rows_raw = db.execute(grouped).all()
    series: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for row in rows_raw:
        labels = [str(val.value if hasattr(val, "value") else val) for val in row[: len(spec.group_by)]]
        label = " / ".join(labels)
        value = int(row[-1])
        series.append({"name": label, "value": value})
        row_obj: dict[str, Any] = {"label": label, "value": value}
        for i, g in enumerate(spec.group_by):
            val = row[i]
            row_obj[g] = val.value if hasattr(val, "value") else val
        rows.append(row_obj)

    total = sum(r["value"] for r in rows)
    return {
        "kind": "aggregate",
        "entity": "finding",
        "group_by": list(spec.group_by),
        "series": series,
        "rows": rows,
        "total": total,
        "drilldown": _drilldown_from_spec(spec),
    }


def _apply_op(stmt, col, f: QueryFilter):
    if f.op == "eq":
        val = _coerce_enum(col, f.value)
        return stmt.where(col == val)
    if f.op == "neq":
        return stmt.where(col != _coerce_enum(col, f.value))
    if f.op == "in":
        if not isinstance(f.value, list):
            raise ValueError("in requires a list value")
        return stmt.where(col.in_([_coerce_enum(col, v) for v in f.value]))
    if f.op == "not_in":
        if not isinstance(f.value, list):
            raise ValueError("not_in requires a list value")
        return stmt.where(~col.in_([_coerce_enum(col, v) for v in f.value]))
    if f.op == "is_null":
        return stmt.where(col.is_(None))
    if f.op == "not_null":
        return stmt.where(col.is_not(None))
    if f.op in ("gt", "gte", "lt", "lte"):
        value = _coerce_comparable(col, f.value)
        if f.op == "gt":
            return stmt.where(col > value)
        if f.op == "gte":
            return stmt.where(col >= value)
        if f.op == "lt":
            return stmt.where(col < value)
        return stmt.where(col <= value)
    raise ValueError(f"unsupported op: {f.op}")


def _coerce_comparable(col, value: Any) -> Any:
    """A stored widget spec is JSON, so a timestamp bound arrives as an ISO-8601 string."""
    if isinstance(getattr(col, "type", None), DateTime) and isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid timestamp for {col.key}: {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return value


def _coerce_enum(col, value: Any) -> Any:
    if value is None:
        return None
    # SQLAlchemy Enum columns
    enum_cls = None
    col_type = getattr(col, "type", None)
    if col_type is not None:
        enum_cls = getattr(col_type, "enum_class", None)
    if enum_cls is None and getattr(col, "key", None) == "status":
        enum_cls = FindingStatus
    if enum_cls is None and getattr(col, "key", None) == "severity":
        enum_cls = Severity
    if enum_cls and isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            return value
    return value


def _connector_value(field: str, *, health: str, sync_mode: str) -> str:
    return health if field == "health" else sync_mode


def _connector_matches(f: QueryFilter, value: str) -> bool:
    if f.op == "eq":
        return value == f.value
    if f.op == "neq":
        return value != f.value
    if not isinstance(f.value, list):
        raise ValueError(f"{f.op} requires a list value")
    return (value in f.value) if f.op == "in" else (value not in f.value)


def _execute_connector(db: Session, *, org_id: uuid.UUID, spec: QuerySpec) -> dict[str, Any]:
    for g in spec.group_by:
        if g not in GROUPABLE_CONNECTOR:
            raise ValueError(f"group_by not allowed for connector: {g}")
    if len(spec.group_by) > 1:
        raise ValueError("connector queries group by at most one field")
    for f in spec.filters:
        if f.field not in CONNECTOR_FIELDS:
            raise ValueError(f"filter field not allowed: {f.field}")
        if f.op not in CONNECTOR_FILTER_OPS:
            raise ValueError(f"filter op not allowed for connector: {f.op}")

    instances = list(db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all())
    last_run_status: dict[uuid.UUID, str] = {}
    last_success_at: dict[uuid.UUID, datetime] = {}
    if instances:
        runs = db.execute(
            select(
                ConnectorRun.connector_instance_id,
                ConnectorRun.status,
                ConnectorRun.started_at,
                ConnectorRun.finished_at,
            )
            .where(ConnectorRun.connector_instance_id.in_([i.id for i in instances]))
            .order_by(ConnectorRun.started_at.desc())
        ).all()
        for instance_id, status, started_at, finished_at in runs:
            last_run_status.setdefault(instance_id, status.value)
            if status == ConnectorRunStatus.SUCCESS and instance_id not in last_success_at:
                last_success_at[instance_id] = finished_at or started_at

    now = datetime.now(UTC)
    buckets: dict[str, int] = {}
    matched = 0
    for inst in instances:
        health = classify_sync_health(
            last_run_status=last_run_status.get(inst.id),
            last_success_at=last_success_at.get(inst.id),
            now=now,
        )
        sync_mode = inst.sync_mode.value
        if not all(
            _connector_matches(f, _connector_value(f.field, health=health, sync_mode=sync_mode)) for f in spec.filters
        ):
            continue
        matched += 1
        if spec.group_by:
            key = _connector_value(spec.group_by[0], health=health, sync_mode=sync_mode)
            buckets[key] = buckets.get(key, 0) + 1

    if not spec.group_by:
        return {
            "kind": "kpi",
            "entity": "connector",
            "series": [{"name": "count", "value": matched}],
            "rows": [{"label": "count", "value": matched}],
            "total": matched,
            "drilldown": {},
        }

    series = [{"name": k, "value": v} for k, v in sorted(buckets.items(), key=lambda x: -x[1])]
    series = series[: spec.limit]
    rows = [{"label": s["name"], "value": s["value"], spec.group_by[0]: s["name"]} for s in series]
    return {
        "kind": "aggregate",
        "entity": "connector",
        "group_by": list(spec.group_by),
        "series": series,
        "rows": rows,
        "total": sum(s["value"] for s in series),
        "drilldown": {},
    }


def _execute_posture_trend(db: Session, *, org_id: uuid.UUID, spec: QuerySpec) -> dict[str, Any]:
    """Daily series from posture_trend_snapshots for line/area widgets."""
    if spec.filters or spec.group_by:
        raise ValueError("posture_trend does not support filters or group_by")
    days = 30
    if spec.time_range and spec.time_range.last:
        days = max(1, _parse_last(spec.time_range.last).days)
    days = min(days, POSTURE_TREND_MAX_DAYS)
    start = date.today() - timedelta(days=days - 1)
    rows = db.scalars(
        select(PostureTrendSnapshot)
        .where(
            PostureTrendSnapshot.org_id == org_id,
            PostureTrendSnapshot.snapshot_date >= start,
        )
        .order_by(PostureTrendSnapshot.snapshot_date.asc())
    ).all()
    series = [
        {
            "date": r.snapshot_date.isoformat(),
            "open_total": sum(int(v) for v in (r.open_by_severity or {}).values()),
            "attention_count": r.attention_count,
            **{f"sev_{k}": int(v) for k, v in (r.open_by_severity or {}).items()},
        }
        for r in rows
    ]
    return {
        "kind": "timeseries",
        "entity": "posture_trend",
        "series": series,
        "rows": series,
        "total": len(series),
        "drilldown": {},
    }
