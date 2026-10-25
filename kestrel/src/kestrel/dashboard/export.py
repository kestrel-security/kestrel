# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard snapshot export: JSON, HTML, PDF, CSV."""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from kestrel.dashboard.boards import get_dashboard
from kestrel.dashboard.extras import dashboard_webhook_summary
from kestrel.dashboard.overview import posture_overview
from kestrel.dashboard.query_dsl import execute_query, parse_query_spec
from kestrel.db.models.dashboard import DashboardExport
from kestrel.db.models.operator import Operator
from kestrel.security.csv_safe import csv_safe_values


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _is_timeseries(data: dict[str, Any]) -> bool:
    """Posture-trend style data: one dict per day keyed by ``date`` rather than
    ``label`` / ``value`` rows."""
    if data.get("kind") == "timeseries":
        return True
    rows = data.get("rows") or []
    return bool(rows) and all(isinstance(r, dict) and "date" in r and "label" not in r for r in rows)


def _timeseries_columns(rows: list[dict[str, Any]]) -> list[str]:
    """``date`` first, then the totals, then ``sev_*`` most to least severe,
    then anything else, so every export lays a trend out the same way."""
    seen: list[str] = []
    for row in rows:
        for key in row:
            if key not in seen:
                seen.append(key)

    def rank(key: str) -> tuple[int, int, str]:
        if key == "date":
            return (0, 0, key)
        if key == "open_total":
            return (1, 0, key)
        if key == "attention_count":
            return (1, 1, key)
        if key.startswith("sev_"):
            level = key.removeprefix("sev_")
            order = _SEVERITY_ORDER.index(level) if level in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
            return (2, order, key)
        return (3, 0, key)

    return sorted(seen, key=rank)


def _cell(value: Any) -> str:
    return "" if value is None else str(value)


def build_snapshot(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
) -> dict[str, Any]:
    """Freeze widget query results at T0 for export/schedule."""
    board = get_dashboard(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)
    overview = posture_overview(db, org_id, viewer_operator_id=operator.id)
    widgets_out: list[dict[str, Any]] = []
    for w in board.get("widgets") or []:
        qspec = w.get("query_spec") or {}
        data: dict[str, Any]
        if qspec.get("preset") or w.get("viz_type") == "preset":
            data = {"kind": "preset", "preset": qspec.get("preset") or w.get("widget_key"), "overview": True}
        elif w.get("viz_type") == "markdown":
            data = {"kind": "markdown", "body": w.get("body_markdown") or ""}
        else:
            try:
                data = execute_query(
                    db,
                    org_id=org_id,
                    spec=parse_query_spec(qspec),
                    viewer_operator_id=operator.id,
                )
            except Exception as exc:  # noqa: BLE001 — surface per-widget errors in snapshot
                data = {"kind": "error", "error": str(exc), "series": [], "rows": []}
        widgets_out.append({**w, "data": data})
    return {
        "exported_at": datetime.now(UTC).isoformat(),
        "dashboard": {k: v for k, v in board.items() if k != "widgets"},
        "widgets": widgets_out,
        "overview": overview,
    }


def snapshot_to_json_bytes(snapshot: dict[str, Any]) -> bytes:
    return json.dumps(snapshot, indent=2, default=str).encode("utf-8")


def snapshot_to_html(snapshot: dict[str, Any]) -> str:
    dash = snapshot.get("dashboard") or {}
    title = _escape(str(dash.get("name") or "Dashboard"))
    exported = _escape(str(snapshot.get("exported_at") or ""))
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>{title}</title>",
        "<style>"
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#111;background:#fff}"
        "h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.5rem}"
        "table{border-collapse:collapse;width:100%;max-width:40rem}"
        "td,th{border:1px solid #ccc;padding:0.35rem 0.5rem;text-align:left}"
        ".muted{color:#666;font-size:0.85rem}"
        "</style></head><body>",
        f"<h1>{title}</h1>",
        f"<p class='muted'>Exported {exported}</p>",
    ]
    for w in snapshot.get("widgets") or []:
        parts.append(f"<h2>{_escape(str(w.get('title') or w.get('widget_key')))}</h2>")
        data = w.get("data") or {}
        if data.get("kind") == "error":
            parts.append(f"<p class='muted'>Error: {_escape(str(data.get('error')))}</p>")
            continue
        if data.get("kind") == "markdown":
            # Plain text only — no HTML from operator markdown in export.
            parts.append(f"<pre>{_escape(str(data.get('body') or ''))}</pre>")
            continue
        if data.get("kind") == "preset":
            preset = data.get("preset")
            overview = snapshot.get("overview") or {}
            parts.append(_preset_html(str(preset), overview))
            continue
        rows = data.get("rows") or []
        if not rows:
            parts.append("<p class='muted'>No data</p>")
            continue
        if _is_timeseries(data):
            columns = _timeseries_columns(rows)
            head = "".join(f"<th>{_escape(c)}</th>" for c in columns)
            parts.append(f"<table><thead><tr>{head}</tr></thead><tbody>")
            for r in rows:
                cells = "".join(f"<td>{_escape(_cell(r.get(c)))}</td>" for c in columns)
                parts.append(f"<tr>{cells}</tr>")
            parts.append("</tbody></table>")
            continue
        parts.append("<table><thead><tr><th>Label</th><th>Value</th></tr></thead><tbody>")
        for r in rows:
            parts.append(f"<tr><td>{_escape(str(r.get('label')))}</td><td>{_escape(str(r.get('value')))}</td></tr>")
        parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _preset_html(preset: str, overview: dict[str, Any]) -> str:
    findings = overview.get("findings") or {}
    connectors = overview.get("connectors") or {}
    if preset == "summary_metrics":
        return (
            "<table><tbody>"
            f"<tr><td>Open findings</td><td>{findings.get('open_total', 0)}</td></tr>"
            f"<tr><td>Healthy connectors</td><td>{connectors.get('healthy', 0)}</td></tr>"
            f"<tr><td>Sync issues</td><td>{connectors.get('failed', 0)}</td></tr>"
            "</tbody></table>"
        )
    if preset == "open_by_severity":
        rows = findings.get("open_by_severity") or {}
        body = "".join(f"<tr><td>{_escape(k)}</td><td>{v}</td></tr>" for k, v in rows.items())
        return f"<table><tbody>{body}</tbody></table>"
    if preset == "by_status":
        rows = findings.get("by_status") or {}
        body = "".join(f"<tr><td>{_escape(k)}</td><td>{v}</td></tr>" for k, v in rows.items())
        return f"<table><tbody>{body}</tbody></table>"
    if preset == "connector_health":
        keys = ("healthy", "failed", "stale", "never_synced", "running")
        body = "".join(f"<tr><td>{k}</td><td>{connectors.get(k, 0)}</td></tr>" for k in keys)
        return f"<table><tbody>{body}</tbody></table>"
    if preset == "top_failing_policies":
        items = (overview.get("policies") or {}).get("top_failing") or []
        body = "".join(
            f"<tr><td>{_escape(str(i.get('name') or i.get('policy_name') or ''))}</td>"
            f"<td>{i.get('open_count', i.get('count', 0))}</td></tr>"
            for i in items
        )
        return f"<table><tbody>{body or '<tr><td colspan=2>None</td></tr>'}</tbody></table>"
    return f"<p class='muted'>Preset {_escape(preset)}</p>"


def snapshot_to_csv_bytes(snapshot: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["widget", "label", "value"])
    for w in snapshot.get("widgets") or []:
        title = w.get("title") or w.get("widget_key")
        data = w.get("data") or {}
        if _is_timeseries(data):
            # One row per date; a header row names this widget's columns
            # (the file-level header's label/value columns do not apply).
            rows = data.get("rows") or []
            columns = _timeseries_columns(rows)
            if columns:
                writer.writerow(csv_safe_values([title, *columns]))
            for r in rows:
                writer.writerow(csv_safe_values([title, *(_cell(r.get(c)) for c in columns)]))
            continue
        for r in data.get("rows") or []:
            writer.writerow(csv_safe_values([title, r.get("label"), r.get("value")]))
        if data.get("kind") == "preset":
            writer.writerow(csv_safe_values([title, "preset", data.get("preset")]))
    return buf.getvalue().encode("utf-8")


def _minimal_pdf(title: str, lines: list[str]) -> bytes:
    """Pure-Python single-page text PDF (no external deps)."""

    # Escape PDF string literals
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_lines = ["BT", "/F1 12 Tf", "50 750 Td", f"({esc(title[:80])}) Tj", "0 -20 Td"]
    for line in lines[:60]:
        content_lines.append(f"({esc(line[:100])}) Tj")
        content_lines.append("0 -14 Td")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects: list[bytes] = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
    )
    objects.append(b"4 0 obj<< /Length " + str(len(stream)).encode() + b" >>stream\n" + stream + b"\nendstream\nendobj\n")
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(f"trailer<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
    return bytes(out)


_PDF_TIMESERIES_DAYS = 10


def _timeseries_pdf_lines(rows: list[dict[str, Any]]) -> list[str]:
    """A compact table of the most recent days (the single-page PDF has no
    room for a 90-day series)."""
    if not rows:
        return ["  No data"]
    columns = _timeseries_columns(rows)
    lines = ["  " + " | ".join(columns)]
    recent = rows[-_PDF_TIMESERIES_DAYS:]
    if len(rows) > len(recent):
        lines.append(f"  (last {len(recent)} of {len(rows)} days)")
    for r in recent:
        lines.append("  " + " | ".join(_cell(r.get(c)) for c in columns))
    return lines


def snapshot_to_pdf_bytes(snapshot: dict[str, Any]) -> bytes:
    dash = snapshot.get("dashboard") or {}
    title = str(dash.get("name") or "Dashboard")
    lines: list[str] = [f"Exported {snapshot.get('exported_at')}", ""]
    for w in snapshot.get("widgets") or []:
        lines.append(str(w.get("title") or w.get("widget_key")))
        data = w.get("data") or {}
        if data.get("kind") == "error":
            lines.append(f"  ERROR: {data.get('error')}")
        elif data.get("kind") == "preset":
            lines.append(f"  (preset: {data.get('preset')})")
        elif _is_timeseries(data):
            lines.extend(_timeseries_pdf_lines(data.get("rows") or []))
        else:
            for r in (data.get("rows") or [])[:15]:
                lines.append(f"  {r.get('label')}: {r.get('value')}")
        lines.append("")
    return _minimal_pdf(title, lines)


def record_export(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator_id: uuid.UUID,
    fmt: str,
    byte_size: int,
) -> DashboardExport:
    row = DashboardExport(
        org_id=org_id,
        dashboard_id=dashboard_id,
        operator_id=operator_id,
        format=fmt,
        byte_size=byte_size,
    )
    db.add(row)
    db.flush()
    return row


def export_dashboard(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    fmt: str,
) -> tuple[bytes, str, str]:
    """Returns (bytes, media_type, filename)."""
    snapshot = build_snapshot(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)
    slug = re.sub(r"[^a-z0-9-]+", "-", str((snapshot.get("dashboard") or {}).get("slug") or "dashboard"))
    fmt = fmt.lower().strip()
    if fmt == "json":
        payload = snapshot_to_json_bytes(snapshot)
        media = "application/json"
        name = f"{slug}.json"
    elif fmt == "html":
        payload = snapshot_to_html(snapshot).encode("utf-8")
        media = "text/html; charset=utf-8"
        name = f"{slug}.html"
    elif fmt == "csv":
        payload = snapshot_to_csv_bytes(snapshot)
        media = "text/csv; charset=utf-8"
        name = f"{slug}.csv"
    elif fmt == "pdf":
        payload = snapshot_to_pdf_bytes(snapshot)
        media = "application/pdf"
        name = f"{slug}.pdf"
    elif fmt == "webhook":
        payload = json.dumps(dashboard_webhook_summary(snapshot), indent=2, default=str).encode("utf-8")
        media = "application/json"
        name = f"{slug}-webhook.json"
    else:
        raise ValueError(f"unsupported format: {fmt}")
    record_export(
        db,
        org_id=org_id,
        dashboard_id=dashboard_id,
        operator_id=operator.id,
        fmt=fmt,
        byte_size=len(payload),
    )
    return payload, media, name
