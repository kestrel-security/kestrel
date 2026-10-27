# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Runs a Python policy against a hand-authored fixture dataset and diffs
matched subjects against expected results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from kestrel.policies.runtime import (
    CompiledPolicy,
    PolicyCompileError,
    PolicyRuntime,
    compile_and_validate,
    get_default_runtime,
)
from kestrel.policies.runtime.helpers import PolicyDataError


@dataclass
class FixtureTestResult:
    passed: bool
    expected_subject_ids: set[str]
    actual_subject_ids: set[str]

    @property
    def missing(self) -> set[str]:
        return self.expected_subject_ids - self.actual_subject_ids

    @property
    def unexpected(self) -> set[str]:
        return self.actual_subject_ids - self.expected_subject_ids


def expand_relative_timestamps(value: Any) -> Any:
    """Replace ``{"$days_ago": n}`` with a datetime ``n`` days before now."""
    if isinstance(value, dict):
        if set(value.keys()) == {"$days_ago"} and isinstance(value["$days_ago"], (int, float)):
            return datetime.now(UTC) - timedelta(days=float(value["$days_ago"]))
        return {k: expand_relative_timestamps(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_relative_timestamps(v) for v in value]
    return value


class FixtureRunError(ValueError):
    """The policy compiled but failed while running over the fixture rows."""


def run_fixture_test_compiled(
    compiled: CompiledPolicy,
    fixtures: dict[str, Any],
    runtime: PolicyRuntime | None = None,
) -> FixtureTestResult:
    """Run ``policy()`` over the fixture rows under ``runtime`` (default: the
    configured runtime, so the API's fixture tests get the subprocess runtime's
    timeout and memory limit rather than running author code in-process)."""
    rows = expand_relative_timestamps(fixtures.get("rows", []))
    runtime = runtime if runtime is not None else get_default_runtime()
    try:
        matched_indices = runtime.match_rows(compiled, rows)
    except PolicyDataError:
        raise  # malformed fixture data, reported as such (docs/policies.md)
    except Exception as exc:
        # A wrong return type, a worker crash, a timeout, or (in the in-process
        # runtime) whatever policy() raised: the draft's fault, not the server's.
        raise FixtureRunError(f"Evaluation failed: {type(exc).__name__}: {exc}") from exc
    matched_ids = {str(rows[index]["_subject_id"]) for index in matched_indices}
    expected = set(fixtures.get("expected_match_subject_ids", []))
    return FixtureTestResult(
        passed=matched_ids == expected,
        expected_subject_ids=expected,
        actual_subject_ids=matched_ids,
    )


def run_fixture_test_dict(source_text: str, fixtures: dict[str, Any]) -> FixtureTestResult:
    try:
        compiled = compile_and_validate(source_text)
    except PolicyCompileError as exc:
        raise ValueError(str(exc)) from exc
    return run_fixture_test_compiled(compiled, fixtures)


def run_fixture_test(source_text: str, fixtures_path: str | Path) -> FixtureTestResult:
    fixtures: dict[str, Any] = json.loads(Path(fixtures_path).read_text())
    return run_fixture_test_dict(source_text, fixtures)
