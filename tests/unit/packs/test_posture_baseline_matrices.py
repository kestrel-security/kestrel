# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The baseline matrices have to describe the policies that actually ship.

`docs/posture-baselines/*.md` is the coverage claim: for each control in a
published baseline, whether Kestrel collects the data, and which `POLICY_ID`
implements the check. It is the number a coverage ratio would be computed from,
and the thing a reader could check against the repository.

It had drifted in both directions. Two GitHub rows were marked `collected`
naming policies that do not exist, so the matrix asserted a shipped check that
was not shipped. Nine more named plausible slugs for planned work. Twenty-six
shipped policies appeared in no row at all, so the denominator was wrong too.
And `gws-posture` had no matrix, which is the one application where an
enumerable published baseline exists.

Prose cannot be trusted to stay in step with code, so this parses the tables and
reconciles them against the packs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from kestrel.policies.packs import get_packs_dir

_MATRIX_DIR = Path(__file__).resolve().parents[3] / "docs" / "posture-baselines"

# Matrix stem -> pack directory. A pack with no matrix fails; see the test.
MATRIX_PACKS = {
    "github": "github-posture",
    "okta": "okta-posture",
    "slack": "slack-posture",
    "google-workspace": "gws-posture",
}

STATUSES = {"collected", "needs-collection", "not-collectable"}
PROFILES = {"L1", "L2", "mon"}
SEVERITIES = {"low", "medium", "high", "critical"}
NO_POLICY = {"—", "-", ""}


class Row(tuple):
    """control, title, profile, required_data, status, policy_cell, severity."""


def _rows(path: Path) -> list[Row]:
    out: list[Row] = []
    for line in path.read_text().splitlines():
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 7:
            continue
        if cells[0] == "Control" or set(cells[0]) <= set("- "):
            continue
        out.append(Row(cells))
    return out


def _policy_ids(cell: str) -> list[str]:
    return re.findall(r"`([a-z0-9][a-z0-9-]*)`", cell)


def _shipped() -> dict[str, str]:
    """POLICY_ID -> pack name, read from the policy modules themselves."""
    out: dict[str, str] = {}
    for path in sorted(get_packs_dir().glob("*/policies/*.py")):
        match = re.search(r'^POLICY_ID\s*=\s*"([^"]+)"', path.read_text(), re.M)
        if match:
            out[match.group(1)] = path.parent.parent.name
    return out


SHIPPED = _shipped()
MATRICES = {stem: _rows(_MATRIX_DIR / f"{stem}.md") for stem in MATRIX_PACKS if (_MATRIX_DIR / f"{stem}.md").exists()}


def test_every_pack_with_policies_has_a_baseline_matrix() -> None:
    packs_with_policies = set(SHIPPED.values())
    missing = sorted(pack for stem, pack in MATRIX_PACKS.items() if pack in packs_with_policies and stem not in MATRICES)
    assert not missing, f"packs with no docs/posture-baselines matrix: {missing}"


@pytest.mark.parametrize("stem", sorted(MATRICES))
def test_no_row_names_a_policy_that_does_not_exist(stem: str) -> None:
    phantom = [
        f"  {row[0]} ({row[4]}): `{pid}`" for row in MATRICES[stem] for pid in _policy_ids(row[5]) if pid not in SHIPPED
    ]
    assert not phantom, (
        f"{stem}.md names policies that do not exist:\n"
        + "\n".join(sorted(phantom))
        + "\nA planned check belongs in an issue, not in a matrix cell."
    )


@pytest.mark.parametrize("stem", sorted(MATRICES))
def test_a_collected_row_implements_the_control(stem: str) -> None:
    """The honesty bug: `collected` is a claim that the check ships."""
    problems = [
        f"  {row[0]} '{row[1]}'"
        for row in MATRICES[stem]
        if row[4] == "collected" and not [p for p in _policy_ids(row[5]) if p in SHIPPED]
    ]
    assert not problems, f"{stem}.md marks these `collected` without naming a shipped policy:\n" + "\n".join(problems)


@pytest.mark.parametrize("stem", sorted(MATRICES))
def test_an_uncollected_row_does_not_claim_a_policy(stem: str) -> None:
    problems = [
        f"  {row[0]} ({row[4]}) names `{row[5]}`"
        for row in MATRICES[stem]
        if row[4] in {"needs-collection", "not-collectable"} and _policy_ids(row[5])
    ]
    assert not problems, (
        f"{stem}.md names a policy on a row whose data is not collected:\n"
        + "\n".join(problems)
        + "\nUse — and track the planned work in a GitHub issue."
    )


@pytest.mark.parametrize("stem", sorted(MATRICES))
def test_every_shipped_policy_appears_in_its_matrix(stem: str) -> None:
    """Without this the ratio has the wrong denominator: a pack could grow
    without the coverage claim moving at all."""
    pack = MATRIX_PACKS[stem]
    named = {pid for row in MATRICES[stem] for pid in _policy_ids(row[5])}
    orphans = sorted(slug for slug, owner in SHIPPED.items() if owner == pack and slug not in named)
    assert not orphans, f"{stem}.md does not mention {len(orphans)} policies shipped by {pack}:\n" + "\n".join(
        f"  {slug}" for slug in orphans
    )


@pytest.mark.parametrize("stem", sorted(MATRICES))
def test_rows_use_the_documented_vocabulary(stem: str) -> None:
    problems: list[str] = []
    for row in MATRICES[stem]:
        if row[4] not in STATUSES:
            problems.append(f"  {row[0]}: status '{row[4]}' not in {sorted(STATUSES)}")
        if row[2] not in PROFILES:
            problems.append(f"  {row[0]}: profile '{row[2]}' not in {sorted(PROFILES)}")
        if row[6] not in SEVERITIES:
            problems.append(f"  {row[0]}: severity '{row[6]}' not in {sorted(SEVERITIES)}")
    assert not problems, f"{stem}.md vocabulary:\n" + "\n".join(problems)


def test_the_parser_actually_found_rows() -> None:
    """Guard: a parser matching nothing would pass every check above."""
    total = sum(len(rows) for rows in MATRICES.values())
    assert len(MATRICES) >= 3, f"only parsed {len(MATRICES)} matrices"
    assert total > 50, f"only parsed {total} rows across all matrices — the table parser is not working"
