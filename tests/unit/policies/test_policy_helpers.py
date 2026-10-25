# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.policies.runtime.helpers`: the shared functions every policy
sandbox gets, and the rule that unreadable data never reads as compliant.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from kestrel.policies.runtime import RestrictedPythonRuntime, worker
from kestrel.policies.runtime.helpers import (
    POLICY_HELPERS,
    PolicyDataError,
    application_matches,
    days_since,
    has_admin_grant,
    parse_timestamp,
    within_last_days,
)
from kestrel.policies.runtime.serialize import rows_to_jsonable
from kestrel.policies.testing import run_fixture_test_dict


def _ago(days: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# --- parse_timestamp --------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC), datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (datetime(2024, 1, 2, 3, 4, 5), datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (date(2024, 1, 2), datetime(2024, 1, 2, tzinfo=UTC)),
        ("2024-01-02T03:04:05Z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02T05:04:05+02:00", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02", datetime(2024, 1, 2, tzinfo=UTC)),
        (1704164645, datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (1704164645.0, datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_accepts_the_shapes_rows_carry(value, expected) -> None:
    assert parse_timestamp(value) == expected


@pytest.mark.parametrize("value", [None, "", "   "])
def test_parse_timestamp_reports_missing_as_none(value) -> None:
    assert parse_timestamp(value) is None


@pytest.mark.parametrize(
    "value",
    ["not a date", "yesterday", "2024-13-45", True, float("nan"), float("inf"), 10**20, [], {}, object()],
)
def test_parse_timestamp_raises_on_malformed_input(value) -> None:
    with pytest.raises(PolicyDataError):
        parse_timestamp(value)


def test_policy_data_error_is_a_value_error() -> None:
    # Callers outside the sandbox that already handle ValueError keep working.
    assert issubclass(PolicyDataError, ValueError)


# --- days_since / within_last_days ------------------------------------------


def test_days_since_measures_elapsed_days() -> None:
    assert days_since(_ago(10)) == pytest.approx(10, abs=0.01)
    assert days_since(None) is None
    assert days_since(datetime.now(UTC) + timedelta(days=1)) < 0


def test_within_last_days_inside_and_outside_the_window() -> None:
    assert within_last_days(_ago(1), 30) is True
    assert within_last_days(_ago(29.9), 30) is True
    assert within_last_days(_ago(30.1), 30) is False
    assert within_last_days(datetime.now(UTC) + timedelta(days=1), 30) is True


def test_within_last_days_treats_missing_as_not_shown_recent() -> None:
    assert within_last_days(None, 30) is False
    assert within_last_days("", 30) is False


def test_within_last_days_raises_rather_than_guessing() -> None:
    # The copies this replaced returned True here, which read as "recent":
    # a dormant account with a garbled last-activity value looked active.
    with pytest.raises(PolicyDataError):
        within_last_days("garbled", 90)


def test_within_last_days_reads_iso_strings_the_in_process_runtime_passes_through() -> None:
    # JSON columns (setting values) reach an in-process policy as strings; the
    # subprocess runtime rehydrates them. Both must give the same answer.
    stale = _ago(200).isoformat()
    assert within_last_days(stale, 90) is False
    assert within_last_days(stale, 90) == within_last_days(datetime.fromisoformat(stale), 90)


# --- has_admin_grant / application_matches ----------------------------------


def test_has_admin_grant() -> None:
    def row(*levels):
        return {"_related": {"grants": [{"grant": {"permission_level": level}} for level in levels]}}

    assert has_admin_grant(row("read", "admin")) is True
    assert has_admin_grant(row("read", "write")) is False
    assert has_admin_grant({}) is False
    assert has_admin_grant({"_related": {"grants": None}}) is False
    assert has_admin_grant({"_related": {"grants": [{"grant": None}]}}) is False


def test_application_matches() -> None:
    crm = {"application": {"type": "harbor-crm", "name": "Sales"}}
    named = {"application": {"type": "other", "name": "Harbor Staging"}}
    other = {"application": {"type": "github", "name": "Acme"}}

    assert application_matches(crm, {"harbor-crm"}) is True
    assert application_matches(named, {"harbor-crm"}, name_contains="harbor") is True
    assert application_matches(other, {"harbor-crm"}, name_contains="harbor") is False
    assert application_matches({}, {"harbor-crm"}, name_contains="harbor") is False


# --- available in every runtime path ----------------------------------------

_HELPER_POLICY = """
POLICY_ID = "helper-probe"
SEVERITY = "low"
RESOURCE_TYPE = "identity"

def policy(resource):
    identity = resource.get("identity") or {}
    return within_last_days(identity.get("last_active_at"), 90)
"""


def _row(subject: str, last_active) -> dict:
    return {
        "_subject_id": uuid.UUID(subject),
        "_subject_type": "identity",
        "identity": {"last_active_at": last_active},
    }


_ACTIVE = "00000000-0000-0000-0000-00000000000a"
_DORMANT = "00000000-0000-0000-0000-00000000000b"
_NEVER = "00000000-0000-0000-0000-00000000000c"


def _rows() -> list[dict]:
    return [_row(_ACTIVE, _ago(5)), _row(_DORMANT, _ago(200)), _row(_NEVER, None)]


def test_every_helper_is_in_the_sandbox_namespace() -> None:
    compiled = RestrictedPythonRuntime().compile(
        'POLICY_ID = "x"\nSEVERITY = "low"\n'
        "def policy(resource):\n"
        f"    return all(callable(f) for f in [{', '.join(POLICY_HELPERS)}])\n"
    )
    assert compiled.policy_fn({}) is True


def test_helpers_work_in_the_in_process_runtime() -> None:
    runtime = RestrictedPythonRuntime()
    result = runtime.evaluate_all(runtime.compile(_HELPER_POLICY), None, uuid.uuid4(), rows=_rows())  # type: ignore[arg-type]
    assert {str(m.subject_id) for m in result.matches} == {_DORMANT, _NEVER}


def test_helpers_work_in_the_subprocess_worker() -> None:
    result = worker._run({"source_text": _HELPER_POLICY, "rows": rows_to_jsonable(_rows())})
    assert result["ok"] is True
    assert {m["subject_id"] for m in result["matches"]} == {_DORMANT, _NEVER}


def test_helpers_work_in_fixture_tests() -> None:
    fixture = {
        "rows": [
            {"_subject_id": "a", "identity": {"last_active_at": {"$days_ago": 5}}},
            {"_subject_id": "b", "identity": {"last_active_at": {"$days_ago": 200}}},
        ],
        "expected_match_subject_ids": ["b"],
    }
    assert run_fixture_test_dict(_HELPER_POLICY, fixture).passed


# --- a malformed value fails the evaluation, visibly -------------------------


def test_malformed_value_fails_the_in_process_evaluation_naming_policy_and_subject() -> None:
    runtime = RestrictedPythonRuntime()
    rows = [*_rows(), _row("00000000-0000-0000-0000-00000000000d", "garbled")]
    with pytest.raises(PolicyDataError) as excinfo:
        runtime.evaluate_all(runtime.compile(_HELPER_POLICY), None, uuid.uuid4(), rows=rows)  # type: ignore[arg-type]
    message = str(excinfo.value)
    assert "helper-probe" in message
    assert "00000000-0000-0000-0000-00000000000d" in message
    assert "garbled" in message


def test_malformed_value_fails_the_worker_evaluation_naming_the_subject() -> None:
    rows = [*_rows(), _row("00000000-0000-0000-0000-00000000000d", "garbled")]
    result = worker._run({"source_text": _HELPER_POLICY, "rows": rows_to_jsonable(rows)})
    assert result["ok"] is False
    assert "PolicyDataError" in result["error"]
    assert "00000000-0000-0000-0000-00000000000d" in result["error"]


def test_malformed_value_fails_a_fixture_test_instead_of_passing_it() -> None:
    fixture = {
        "rows": [{"_subject_id": "a", "identity": {"last_active_at": "garbled"}}],
        "expected_match_subject_ids": [],
    }
    with pytest.raises(PolicyDataError):
        run_fixture_test_dict(_HELPER_POLICY, fixture)
