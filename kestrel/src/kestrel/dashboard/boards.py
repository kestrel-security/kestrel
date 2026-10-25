# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Multi-dashboard CRUD and default-board seeding."""

from __future__ import annotations

import re
import uuid
from copy import deepcopy
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.dashboard.presets import BOARD_TEMPLATES, PRESET_WIDGETS, catalog_presets, default_widget_defs
from kestrel.dashboard.query_dsl import parse_query_spec
from kestrel.db.models.dashboard import (
    Dashboard,
    DashboardVisibility,
    DashboardVizType,
    DashboardWidget,
)
from kestrel.db.models.operator import Operator, OperatorRole

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def slugify(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or "dashboard"


def _widget_to_dict(w: DashboardWidget) -> dict[str, Any]:
    return {
        "id": str(w.id),
        "widget_key": w.widget_key,
        "title": w.title,
        "viz_type": w.viz_type.value,
        "query_spec": w.query_spec,
        "layout": w.layout,
        "refresh_seconds": w.refresh_seconds,
        "sort_order": w.sort_order,
        "body_markdown": w.body_markdown,
    }


def _dashboard_to_dict(d: Dashboard, widgets: list[DashboardWidget] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(d.id),
        "name": d.name,
        "slug": d.slug,
        "description": d.description,
        "is_default": d.is_default,
        "visibility": d.visibility.value,
        "created_by_operator_id": str(d.created_by_operator_id) if d.created_by_operator_id else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }
    if widgets is not None:
        out["widgets"] = [_widget_to_dict(w) for w in sorted(widgets, key=lambda x: (x.sort_order, x.created_at))]
    return out


def _visible_to(operator: Operator, d: Dashboard) -> bool:
    if d.visibility == DashboardVisibility.ORG:
        return True
    if d.created_by_operator_id == operator.id:
        return True
    return operator.role == OperatorRole.ADMIN


def _require_editable(operator: Operator, d: Dashboard, what: str) -> None:
    """Changing a board is for its owner or an admin.

    Visibility only gates reading: an org board (Home included) is shared, so
    an analyst who did not create it must not retitle it, re-scope it to
    private, or rewrite its widgets out from under everyone else.
    """
    if operator.role == OperatorRole.READ_ONLY:
        raise PermissionError(f"read-only operators cannot edit {what}")
    if operator.role == OperatorRole.ADMIN:
        return
    # Home is seeded by whoever lists dashboards first, so its creator column
    # names an accident, not an owner.
    if d.is_default or d.created_by_operator_id != operator.id:
        raise PermissionError(f"only the owner or an admin can edit this dashboard's {what}")


def ensure_default_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    created_by: uuid.UUID | None = None,
) -> Dashboard:
    """Idempotently create the org Home board with default preset widgets."""
    existing = db.scalars(select(Dashboard).where(Dashboard.org_id == org_id, Dashboard.is_default.is_(True))).first()
    if existing:
        return existing

    dash = Dashboard(
        org_id=org_id,
        name="Home",
        slug="home",
        description="Default posture overview",
        is_default=True,
        visibility=DashboardVisibility.ORG,
        created_by_operator_id=created_by,
    )
    db.add(dash)
    db.flush()

    for i, meta in enumerate(default_widget_defs()):
        w = DashboardWidget(
            org_id=org_id,
            dashboard_id=dash.id,
            widget_key=meta["widget_key"],
            title=meta["title"],
            viz_type=DashboardVizType(meta["viz_type"]),
            query_spec=deepcopy(meta["query_spec"]),
            layout=deepcopy(meta["layout"]),
            sort_order=i,
        )
        db.add(w)
    db.flush()
    return dash


def list_dashboards(db: Session, *, org_id: uuid.UUID, operator: Operator) -> list[dict[str, Any]]:
    ensure_default_dashboard(db, org_id=org_id, created_by=operator.id)
    rows = list(db.scalars(select(Dashboard).where(Dashboard.org_id == org_id).order_by(Dashboard.name)).all())
    return [_dashboard_to_dict(d) for d in rows if _visible_to(operator, d)]


def get_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
) -> dict[str, Any]:
    ensure_default_dashboard(db, org_id=org_id, created_by=operator.id)
    d = db.scalars(select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None or not _visible_to(operator, d):
        raise LookupError("dashboard not found")
    widgets = list(
        db.scalars(
            select(DashboardWidget).where(
                DashboardWidget.dashboard_id == d.id,
                DashboardWidget.org_id == org_id,
            )
        ).all()
    )
    return _dashboard_to_dict(d, widgets)


def create_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator: Operator,
    name: str,
    slug: str | None = None,
    description: str | None = None,
    visibility: str = "org",
    template: str | None = None,
) -> dict[str, Any]:
    if operator.role == OperatorRole.READ_ONLY:
        raise PermissionError("read-only operators cannot create dashboards")
    slug_val = slugify(slug or name)
    if not _SLUG_RE.match(slug_val):
        raise ValueError("invalid slug")
    clash = db.scalars(select(Dashboard).where(Dashboard.org_id == org_id, Dashboard.slug == slug_val)).first()
    if clash:
        raise ValueError(f"slug already exists: {slug_val}")

    vis = DashboardVisibility(visibility)
    # Analysts create private boards; admins publish org boards.
    if vis == DashboardVisibility.ORG and operator.role == OperatorRole.ANALYST:
        vis = DashboardVisibility.PRIVATE

    dash = Dashboard(
        org_id=org_id,
        name=name.strip()[:200],
        slug=slug_val,
        description=description,
        is_default=False,
        visibility=vis,
        created_by_operator_id=operator.id,
    )
    db.add(dash)
    db.flush()

    if template:
        _seed_from_template(db, org_id=org_id, dashboard=dash, template_slug=template)
    db.flush()
    return get_dashboard(db, org_id=org_id, dashboard_id=dash.id, operator=operator)


def _seed_from_template(db: Session, *, org_id: uuid.UUID, dashboard: Dashboard, template_slug: str) -> None:
    tmpl = next((t for t in BOARD_TEMPLATES if t["slug"] == template_slug), None)
    if tmpl is None:
        raise ValueError(f"unknown template: {template_slug}")
    extra = tmpl.get("extra_filters") or {}
    # Pack widgets into a non-overlapping Home-style layout (catalog layouts can collide).
    packed: list[dict[str, int]] = [
        {"x": 0, "y": 0, "w": 12, "h": 3},  # KPI strip
        {"x": 0, "y": 3, "w": 6, "h": 5},
        {"x": 6, "y": 3, "w": 6, "h": 5},
        {"x": 0, "y": 8, "w": 6, "h": 5},
        {"x": 6, "y": 8, "w": 6, "h": 5},
    ]
    for i, key in enumerate(tmpl["widget_keys"]):
        meta = PRESET_WIDGETS.get(key)
        if not meta:
            continue
        qspec = deepcopy(meta["query_spec"])
        if extra.get("application_type") and qspec.get("entity") == "finding":
            filters = list(qspec.get("filters") or [])
            filters.append({"field": "application_type", "op": "eq", "value": extra["application_type"]})
            qspec["filters"] = filters
        layout = packed[i] if i < len(packed) else {"x": 0, "y": 8 + i * 5, "w": 6, "h": 5}
        w = DashboardWidget(
            org_id=org_id,
            dashboard_id=dashboard.id,
            widget_key=key,
            title=meta["title"],
            viz_type=DashboardVizType(meta["viz_type"]),
            query_spec=qspec,
            layout=layout,
            sort_order=i,
        )
        db.add(w)


def update_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    name: str | None = None,
    description: str | None = None,
    visibility: str | None = None,
) -> dict[str, Any]:
    d = db.scalars(select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None or not _visible_to(operator, d):
        raise LookupError("dashboard not found")
    _require_editable(operator, d, "dashboards")
    if name is not None:
        d.name = name.strip()[:200]
    if description is not None:
        d.description = description
    if visibility is not None:
        if operator.role != OperatorRole.ADMIN and visibility == "org":
            raise PermissionError("only admins can publish org dashboards")
        d.visibility = DashboardVisibility(visibility)
    db.add(d)
    db.flush()
    return get_dashboard(db, org_id=org_id, dashboard_id=d.id, operator=operator)


def delete_dashboard(db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID, operator: Operator) -> None:
    d = db.scalars(select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None:
        raise LookupError("dashboard not found")
    if d.is_default:
        raise ValueError("cannot delete the default Home dashboard")
    if operator.role != OperatorRole.ADMIN and d.created_by_operator_id != operator.id:
        raise PermissionError("cannot delete this dashboard")
    _unpin_home_for_all(db, org_id=org_id, dashboard_id=dashboard_id)
    db.delete(d)
    db.flush()


def _unpin_home_for_all(db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID) -> None:
    """Drop personal home pins referencing a board that is going away."""
    pinned = db.scalars(
        select(Operator).where(
            Operator.org_id == org_id,
            Operator.ui_preferences["dashboard_home_id"].astext == str(dashboard_id),
        )
    ).all()
    for op in pinned:
        prefs = dict(op.ui_preferences or {})
        prefs.pop("dashboard_home_id", None)
        op.ui_preferences = prefs
        db.add(op)


def duplicate_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    name: str | None = None,
) -> dict[str, Any]:
    src = get_dashboard(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)
    new_name = name or f"{src['name']} (copy)"
    created = create_dashboard(
        db,
        org_id=org_id,
        operator=operator,
        name=new_name,
        visibility="private" if operator.role != OperatorRole.ADMIN else src["visibility"],
    )
    # Copy widgets
    for i, w in enumerate(src.get("widgets") or []):
        add_widget(
            db,
            org_id=org_id,
            dashboard_id=uuid.UUID(created["id"]),
            operator=operator,
            widget_key=w["widget_key"],
            title=w["title"],
            viz_type=w["viz_type"],
            query_spec=w["query_spec"],
            layout=w["layout"],
            sort_order=i,
            body_markdown=w.get("body_markdown"),
        )
    return get_dashboard(db, org_id=org_id, dashboard_id=uuid.UUID(created["id"]), operator=operator)


def set_default_dashboard(db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID, operator: Operator) -> dict[str, Any]:
    if operator.role != OperatorRole.ADMIN:
        raise PermissionError("only admins can set the org default dashboard")
    d = db.scalars(select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None:
        raise LookupError("dashboard not found")
    for other in db.scalars(select(Dashboard).where(Dashboard.org_id == org_id)).all():
        other.is_default = other.id == d.id
        db.add(other)
    db.flush()
    return get_dashboard(db, org_id=org_id, dashboard_id=d.id, operator=operator)


def pin_home(db: Session, *, operator: Operator, dashboard_id: uuid.UUID | None) -> dict[str, Any]:
    prefs = dict(operator.ui_preferences or {})
    if dashboard_id is None:
        prefs.pop("dashboard_home_id", None)
    else:
        prefs["dashboard_home_id"] = str(dashboard_id)
    operator.ui_preferences = prefs
    db.add(operator)
    db.flush()
    return {"dashboard_home_id": prefs.get("dashboard_home_id")}


def _validated_query_spec(viz_type: DashboardVizType, query_spec: dict[str, Any]) -> dict[str, Any]:
    """Reject a spec that would fail every time the widget renders. Markdown widgets carry no query."""
    if viz_type != DashboardVizType.MARKDOWN:
        parse_query_spec(query_spec)
    return query_spec


def add_widget(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    widget_key: str,
    title: str,
    viz_type: str,
    query_spec: dict[str, Any],
    layout: dict[str, Any] | None = None,
    sort_order: int = 0,
    body_markdown: str | None = None,
    refresh_seconds: int | None = None,
) -> dict[str, Any]:
    d = db.scalars(select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None or not _visible_to(operator, d):
        raise LookupError("dashboard not found")
    _require_editable(operator, d, "widgets")

    layout = layout or {"x": 0, "y": 0, "w": 6, "h": 3}
    for k in ("x", "y", "w", "h"):
        if k not in layout:
            raise ValueError("layout must include x, y, w, h")
    viz = DashboardVizType(viz_type)
    w = DashboardWidget(
        org_id=org_id,
        dashboard_id=dashboard_id,
        widget_key=widget_key[:80],
        title=title[:200],
        viz_type=viz,
        query_spec=_validated_query_spec(viz, query_spec),
        layout=layout,
        sort_order=sort_order,
        body_markdown=body_markdown,
        refresh_seconds=refresh_seconds,
    )
    db.add(w)
    db.flush()
    return _widget_to_dict(w)


def update_widget(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    operator: Operator,
    **fields: Any,
) -> dict[str, Any]:
    w = db.scalars(
        select(DashboardWidget).where(
            DashboardWidget.id == widget_id,
            DashboardWidget.dashboard_id == dashboard_id,
            DashboardWidget.org_id == org_id,
        )
    ).first()
    if w is None:
        raise LookupError("widget not found")
    d = db.scalars(select(Dashboard).where(Dashboard.id == w.dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None or not _visible_to(operator, d):
        raise LookupError("dashboard not found")
    _require_editable(operator, d, "widgets")
    if "title" in fields and fields["title"] is not None:
        w.title = str(fields["title"])[:200]
    if "viz_type" in fields and fields["viz_type"] is not None:
        w.viz_type = DashboardVizType(fields["viz_type"])
    if "query_spec" in fields and fields["query_spec"] is not None:
        w.query_spec = _validated_query_spec(w.viz_type, fields["query_spec"])
    if "layout" in fields and fields["layout"] is not None:
        w.layout = fields["layout"]
    if "sort_order" in fields and fields["sort_order"] is not None:
        w.sort_order = int(fields["sort_order"])
    if "body_markdown" in fields:
        w.body_markdown = fields["body_markdown"]
    if "refresh_seconds" in fields:
        w.refresh_seconds = fields["refresh_seconds"]
    db.add(w)
    db.flush()
    return _widget_to_dict(w)


def delete_widget(
    db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID, widget_id: uuid.UUID, operator: Operator
) -> None:
    w = db.scalars(
        select(DashboardWidget).where(
            DashboardWidget.id == widget_id,
            DashboardWidget.dashboard_id == dashboard_id,
            DashboardWidget.org_id == org_id,
        )
    ).first()
    if w is None:
        raise LookupError("widget not found")
    d = db.scalars(select(Dashboard).where(Dashboard.id == w.dashboard_id, Dashboard.org_id == org_id)).first()
    if d is None or not _visible_to(operator, d):
        raise LookupError("widget not found")
    _require_editable(operator, d, "widgets")
    db.delete(w)
    db.flush()


def save_layouts(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    layouts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Batch-update widget positions: [{id, layout, sort_order?}]."""
    d = get_dashboard(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)
    # update_widget checks again per widget; checking up front keeps a refused
    # batch from applying half its moves first.
    board = db.get(Dashboard, dashboard_id)
    assert board is not None  # get_dashboard raised LookupError otherwise
    _require_editable(operator, board, "layouts")
    by_id = {w["id"]: w for w in d["widgets"]}
    for item in layouts:
        wid = str(item["id"])
        if wid not in by_id:
            raise ValueError(f"unknown widget id: {wid}")
        update_widget(
            db,
            org_id=org_id,
            dashboard_id=dashboard_id,
            widget_id=uuid.UUID(wid),
            operator=operator,
            layout=item.get("layout"),
            sort_order=item.get("sort_order"),
        )
    return get_dashboard(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)


def add_preset_widget(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    preset_id: str,
) -> dict[str, Any]:
    meta = PRESET_WIDGETS.get(preset_id)
    if meta is None:
        raise ValueError(f"unknown preset: {preset_id}")
    return add_widget(
        db,
        org_id=org_id,
        dashboard_id=dashboard_id,
        operator=operator,
        widget_key=preset_id,
        title=meta["title"],
        viz_type=meta["viz_type"],
        query_spec=deepcopy(meta["query_spec"]),
        layout=deepcopy(meta["layout"]),
    )


def list_templates() -> list[dict[str, Any]]:
    return [
        {
            "slug": t["slug"],
            "name": t["name"],
            "description": t["description"],
            "widget_keys": t["widget_keys"],
        }
        for t in BOARD_TEMPLATES
    ]


def presets_payload() -> dict[str, Any]:
    return {"presets": catalog_presets(), "templates": list_templates()}
