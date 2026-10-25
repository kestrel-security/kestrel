# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Custom policy fixture persistence + capture from live matches.

Fixtures for ``source=custom`` policies live on ``Policy.fixtures`` (JSONB).
Pack policies remain file-owned under ``packs/*/policies/fixtures/``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.policy import Policy, PolicySource
from kestrel.policies.dataload import RESOURCE_TYPE_TO_FROM_TYPE, load_rows
from kestrel.policies.runtime import PolicyCompileError, get_default_runtime
from kestrel.policies.runtime.serialize import row_to_jsonable

DEFAULT_CAPTURE_CAP = 50
MAX_CAPTURE_CAP = 200
MAX_FIXTURE_ROWS = 500


class CustomFixtureError(Exception):
    """Raised when fixtures cannot be validated or captured."""


def validate_fixture_payload(fixtures: dict[str, Any]) -> dict[str, Any]:
    """Normalize and validate fixture JSON shape used by ``kestrel policy test``."""
    if not isinstance(fixtures, dict):
        raise CustomFixtureError("fixtures must be a JSON object")
    rows = fixtures.get("rows")
    if not isinstance(rows, list):
        raise CustomFixtureError("fixtures.rows must be a list")
    if len(rows) > MAX_FIXTURE_ROWS:
        raise CustomFixtureError(f"fixtures.rows exceeds max of {MAX_FIXTURE_ROWS}")
    expected = fixtures.get("expected_match_subject_ids", [])
    if expected is None:
        expected = []
    if not isinstance(expected, list):
        raise CustomFixtureError("fixtures.expected_match_subject_ids must be a list")
    for item in expected:
        if not isinstance(item, (str, int)):
            raise CustomFixtureError("fixtures.expected_match_subject_ids items must be strings")
    return {
        "rows": rows,
        "expected_match_subject_ids": [str(x) for x in expected],
        **{k: v for k, v in fixtures.items() if k not in ("rows", "expected_match_subject_ids")},
    }


def get_custom_fixtures(policy: Policy) -> dict[str, Any] | None:
    """Return stored custom fixtures, or None when unset / not custom."""
    if policy.source != PolicySource.CUSTOM:
        return None
    raw = policy.fixtures
    return raw if isinstance(raw, dict) else None


def set_custom_fixtures(policy: Policy, fixtures: dict[str, Any] | None) -> dict[str, Any] | None:
    """Persist validated fixtures on a custom policy (None clears). Pack → error."""
    if policy.source != PolicySource.CUSTOM:
        raise CustomFixtureError("Fixtures can only be saved for custom policies")
    if fixtures is None:
        policy.fixtures = None
        return None
    validated = validate_fixture_payload(fixtures)
    policy.fixtures = validated
    return validated


def _attach_related_grants(session: Session, org_id: uuid.UUID, rows: list[dict[str, Any]]) -> None:
    by_subject: dict[Any, list[dict[str, Any]]] = {}
    for related in load_rows(session, org_id, "grants"):
        by_subject.setdefault(related["_subject_id"], []).append(related)
    for row in rows:
        related = row.setdefault("_related", {})
        related["grants"] = by_subject.get(row["_subject_id"], [])


def capture_fixture_from_live_matches(
    db: Session,
    org_id: uuid.UUID,
    source_text: str,
    *,
    subject_ids: list[str] | None = None,
    max_rows: int = DEFAULT_CAPTURE_CAP,
) -> dict[str, Any]:
    """Build fixture JSON from live inventory rows that match the policy.

    When ``subject_ids`` is provided (e.g. from a dry-run response), only those
    subjects are included. Otherwise all current matches are captured.
    Rows and ``expected_match_subject_ids`` are capped.
    """
    cap = max(1, min(int(max_rows), MAX_CAPTURE_CAP))
    runtime = get_default_runtime()
    try:
        compiled = runtime.compile(source_text)
    except PolicyCompileError as exc:
        raise CustomFixtureError(f"Compile failed: {exc}") from exc

    resource_type = compiled.contract.resource_type
    from_type = RESOURCE_TYPE_TO_FROM_TYPE.get(resource_type)
    if from_type is None:
        raise CustomFixtureError(f"Unsupported RESOURCE_TYPE for capture: {resource_type!r}")

    rows = load_rows(db, org_id, from_type)
    if from_type == "identities":
        _attach_related_grants(db, org_id, rows)

    wanted: set[str] | None = None
    if subject_ids is not None:
        wanted = {str(s) for s in subject_ids if s}

    candidates = [row for row in rows if wanted is None or str(row.get("_subject_id")) in wanted]
    # Through the runtime, not compiled.policy_fn: this runs author code over
    # live rows inside the API, so it needs the runtime's isolation and limits.
    try:
        matched_indices = runtime.match_rows(compiled, candidates)
    except (TypeError, ValueError, RuntimeError, TimeoutError) as exc:
        raise CustomFixtureError(f"Evaluation failed: {exc}") from exc
    total_matches = len(matched_indices)
    matched_rows = [candidates[index] for index in matched_indices[:cap]]

    jsonable_rows = [row_to_jsonable(r) for r in matched_rows]
    expected = [str(r.get("_subject_id")) for r in jsonable_rows]
    return {
        "fixtures": {
            "rows": jsonable_rows,
            "expected_match_subject_ids": expected,
        },
        "row_count": len(jsonable_rows),
        "truncated": total_matches > len(matched_rows),
        "max_rows": cap,
        "resource_type": resource_type,
    }
