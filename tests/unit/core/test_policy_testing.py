# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.policies.testing`: runs a compiled policy against a
hand-authored fixture dataset and diffs matched subjects against expected
results. Every fixture here is built inline by the test -- none of it reads
a shipped pack fixture (rule 2 of docs/testing.md).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kestrel.policies.runtime.types import CompiledPolicy
from kestrel.policies.testing import (
    FixtureRunError,
    FixtureTestResult,
    run_fixture_test_compiled,
    run_fixture_test_dict,
)

_MFA_POLICY_SOURCE = """
POLICY_ID = "tmp-mfa-required"
TITLE = "MFA required"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Compliant only when MFA is enabled."

def policy(resource):
    return bool(resource["identity"]["mfa_enabled"])
"""

_NON_BOOL_POLICY_SOURCE = """
POLICY_ID = "tmp-non-bool"
TITLE = "Returns the wrong type"
SEVERITY = "low"
RESOURCE_TYPE = "identity"
DESCRIPTION = "policy() returns a string instead of bool."

def policy(resource):
    return "yes"
"""


def _fixture(*, no_mfa_ids: list[str], mfa_ids: list[str], expected: list[str]) -> dict:
    rows = [{"_subject_id": subject_id, "identity": {"mfa_enabled": False}} for subject_id in no_mfa_ids] + [
        {"_subject_id": subject_id, "identity": {"mfa_enabled": True}} for subject_id in mfa_ids
    ]
    return {"rows": rows, "expected_match_subject_ids": expected}


def test_matching_fixture_passes_with_empty_missing_and_unexpected():
    fixture = _fixture(no_mfa_ids=["s1", "s2"], mfa_ids=["s3"], expected=["s1", "s2"])

    result = run_fixture_test_dict(_MFA_POLICY_SOURCE, fixture)

    assert isinstance(result, FixtureTestResult)
    assert result.passed is True
    assert result.missing == set()
    assert result.unexpected == set()
    assert result.actual_subject_ids == {"s1", "s2"}


def test_a_wrong_expectation_fails_with_precise_missing_and_unexpected_sets():
    # s1 has no MFA (the policy will match it) but the fixture claims s2
    # instead -- s2 is never matched (it has MFA), so it is "missing", and
    # s1 is matched but not expected, so it is "unexpected".
    fixture = _fixture(no_mfa_ids=["s1"], mfa_ids=["s2"], expected=["s2"])

    result = run_fixture_test_dict(_MFA_POLICY_SOURCE, fixture)

    assert result.passed is False
    assert result.missing == {"s2"}
    assert result.unexpected == {"s1"}
    assert result.expected_subject_ids == {"s2"}


def test_missing_reports_expected_subjects_the_policy_never_matched():
    fixture = _fixture(no_mfa_ids=[], mfa_ids=["s1"], expected=["s1"])

    result = run_fixture_test_dict(_MFA_POLICY_SOURCE, fixture)

    assert result.passed is False
    assert result.missing == {"s1"}
    assert result.unexpected == set()


def test_empty_rows_and_empty_expectation_passes_trivially():
    result = run_fixture_test_dict(_MFA_POLICY_SOURCE, {"rows": [], "expected_match_subject_ids": []})

    assert result.passed is True
    assert result.actual_subject_ids == set()


def test_missing_fixture_keys_default_to_empty():
    result = run_fixture_test_dict(_MFA_POLICY_SOURCE, {})

    assert result.passed is True
    assert result.expected_subject_ids == set()
    assert result.actual_subject_ids == set()


def test_a_policy_returning_a_non_bool_fails_the_fixture_run():
    fixture = {"rows": [{"_subject_id": "s1"}], "expected_match_subject_ids": []}

    with pytest.raises(FixtureRunError, match="bool"):
        run_fixture_test_dict(_NON_BOOL_POLICY_SOURCE, fixture)


def test_source_that_fails_to_compile_raises_value_error():
    broken_source = "POLICY_ID = 42\n"  # POLICY_ID must be a non-empty string

    with pytest.raises(ValueError, match="POLICY_ID"):
        run_fixture_test_dict(broken_source, {"rows": [], "expected_match_subject_ids": []})


def test_run_fixture_test_compiled_accepts_an_already_compiled_policy():
    from kestrel.policies.runtime.factory import compile_and_validate

    compiled = compile_and_validate(_MFA_POLICY_SOURCE)
    assert isinstance(compiled, CompiledPolicy)

    fixture = _fixture(no_mfa_ids=["s1"], mfa_ids=[], expected=["s1"])
    result = run_fixture_test_compiled(compiled, fixture)

    assert result.passed is True


def test_days_ago_macro_expands_to_a_real_datetime_before_the_policy_runs():
    dt_policy_source = """
POLICY_ID = "tmp-dormant-check"
TITLE = "Flags rows whose timestamp field is not a real datetime"
SEVERITY = "low"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Exercises the $days_ago fixture macro."

def policy(resource):
    # Only a real datetime has `.year`; the raw {"$days_ago": ...} dict
    # would raise a KeyError here if the macro had not been expanded.
    return resource["seen_at"].year > 2000
"""
    fixture = {
        "rows": [{"_subject_id": "s1", "seen_at": {"$days_ago": 30}}],
        "expected_match_subject_ids": [],
    }

    result = run_fixture_test_dict(dt_policy_source, fixture)

    # The macro expands before the policy runs, so the row is compliant
    # (`.year > 2000` is True) -- it never matches.
    assert result.passed is True
    assert result.actual_subject_ids == set()


def test_days_ago_macro_produces_a_value_close_to_now_minus_the_offset():
    from kestrel.policies.testing import _expand_relative_timestamps

    expanded = _expand_relative_timestamps({"seen_at": {"$days_ago": 10}})
    expected = datetime.now(UTC) - timedelta(days=10)

    assert abs((expanded["seen_at"] - expected).total_seconds()) < 5
