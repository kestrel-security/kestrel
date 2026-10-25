# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Posture-trend widgets return a timeseries (``date`` / ``open_total`` /
``attention_count`` / ``sev_*`` per day), not ``label`` / ``value`` rows.
The CSV, PDF, and HTML exports used to read only ``label`` / ``value``, so a
trend widget came out as ``Title,,`` rows and ``None: None`` lines."""

from __future__ import annotations

import csv
import io

from kestrel.dashboard.export import snapshot_to_csv_bytes, snapshot_to_html, snapshot_to_pdf_bytes

_SERIES = [
    {"date": "2026-10-01", "open_total": 7, "attention_count": 2, "sev_high": 3, "sev_critical": 1, "sev_low": 3},
    {"date": "2026-10-02", "open_total": 5, "attention_count": 1, "sev_high": 2, "sev_critical": 1, "sev_low": 2},
]


def _snapshot() -> dict:
    return {
        "exported_at": "2026-10-03T00:00:00+00:00",
        "dashboard": {"name": "Posture"},
        "widgets": [
            {
                "title": "Posture trend",
                "viz_type": "line",
                "data": {"kind": "timeseries", "entity": "posture_trend", "series": _SERIES, "rows": _SERIES},
            },
            {
                "title": "By severity",
                "viz_type": "bar",
                "data": {"kind": "aggregate", "rows": [{"label": "high", "value": 4}]},
            },
        ],
    }


def test_csv_writes_a_row_per_date_with_the_series_columns() -> None:
    rows = list(csv.reader(io.StringIO(snapshot_to_csv_bytes(_snapshot()).decode())))

    trend = [r for r in rows if r[0] == "Posture trend"]
    assert trend[0] == [
        "Posture trend",
        "date",
        "open_total",
        "attention_count",
        "sev_critical",
        "sev_high",
        "sev_low",
    ]
    assert trend[1] == ["Posture trend", "2026-10-01", "7", "2", "1", "3", "3"]
    assert trend[2] == ["Posture trend", "2026-10-02", "5", "1", "1", "2", "2"]
    # No empty label/value rows for the trend widget.
    assert all(cell != "" for row in trend for cell in row)
    # Ordinary label/value widgets are unchanged.
    assert ["By severity", "high", "4"] in rows


def test_pdf_summarises_the_timeseries_instead_of_none() -> None:
    pdf = snapshot_to_pdf_bytes(_snapshot())

    assert b"None: None" not in pdf
    assert b"2026-10-01" in pdf
    assert b"2026-10-02" in pdf
    assert b"date | open_total | attention_count" in pdf
    assert b"high: 4" in pdf


def test_html_renders_a_column_per_series_field() -> None:
    html = snapshot_to_html(_snapshot())

    assert "<th>date</th>" in html
    assert "<th>sev_critical</th>" in html
    assert "<td>2026-10-02</td>" in html
    assert "<td>None</td>" not in html
