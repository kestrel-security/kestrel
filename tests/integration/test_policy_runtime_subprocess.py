# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The subprocess policy runtime, through a real child process.

The rest of the suite sets `KESTREL_POLICY_RUNTIME=restricted`, so without
these the production default (`subprocess`) never actually runs a worker. No
database: rows are passed in directly.
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.policies.runtime import SubprocessPolicyRuntime
from kestrel.policies.testing import FixtureRunError

_HEADER = 'POLICY_ID = "subprocess-probe"\nSEVERITY = "low"\nRESOURCE_TYPE = "identity"\n'


def _rows() -> list[dict]:
    return [
        {
            "_subject_id": uuid.UUID("00000000-0000-0000-0000-00000000000a"),
            "_subject_type": "identity",
            "identity": {"last_active_at": datetime.now(UTC) - timedelta(days=5)},
        },
        {
            "_subject_id": uuid.UUID("00000000-0000-0000-0000-00000000000b"),
            "_subject_type": "identity",
            "identity": {"last_active_at": datetime.now(UTC) - timedelta(days=200)},
        },
    ]


def _evaluate(runtime: SubprocessPolicyRuntime, body: str, rows: list[dict] | None = None):
    source = _HEADER + "\ndef policy(resource):\n" + "".join(f"    {line}\n" for line in body.splitlines())
    compiled = runtime.compile(source)
    # `session` is only used to load rows, and rows are passed in.
    return runtime.evaluate_all(compiled, None, uuid.uuid4(), rows=rows or _rows())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "body",
    ["while True:\n    pass", "time.sleep(3600)\nreturn True"],
    ids=["busy_loop", "sleep"],
)
def test_a_policy_that_never_returns_is_killed_at_the_timeout(body: str) -> None:
    runtime = SubprocessPolicyRuntime(timeout_seconds=1)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        _evaluate(runtime, body)
    assert time.monotonic() - started < 15


def test_shared_helpers_are_available_in_the_worker() -> None:
    result = _evaluate(
        SubprocessPolicyRuntime(),
        'return within_last_days((resource.get("identity") or {}).get("last_active_at"), 90)',
    )
    assert [str(m.subject_id) for m in result.matches] == ["00000000-0000-0000-0000-00000000000b"]


def test_a_malformed_timestamp_fails_the_evaluation_instead_of_passing() -> None:
    rows = _rows()
    rows[1]["identity"]["last_active_at"] = "garbled"
    with pytest.raises(RuntimeError, match=r"PolicyDataError.*00000000-0000-0000-0000-00000000000b"):
        _evaluate(
            SubprocessPolicyRuntime(),
            'return within_last_days((resource.get("identity") or {}).get("last_active_at"), 90)',
            rows,
        )


_FIXTURES = {
    "rows": [
        {"_subject_id": "active", "identity": {"last_active_at": {"$days_ago": 5}}},
        {"_subject_id": "dormant", "identity": {"last_active_at": {"$days_ago": 200}}},
    ],
    "expected_match_subject_ids": ["dormant"],
}


def _fixture_test(runtime: SubprocessPolicyRuntime, body: str):
    from kestrel.policies.testing import run_fixture_test_compiled

    source = _HEADER + "\ndef policy(resource):\n" + "".join(f"    {line}\n" for line in body.splitlines())
    return run_fixture_test_compiled(runtime.compile(source), _FIXTURES, runtime=runtime)


def test_fixture_tests_run_in_the_worker() -> None:
    result = _fixture_test(
        SubprocessPolicyRuntime(),
        'return within_last_days((resource.get("identity") or {}).get("last_active_at"), 90)',
    )
    assert result.passed
    assert result.actual_subject_ids == {"dormant"}


def test_match_rows_keeps_indices_across_batches() -> None:
    runtime = SubprocessPolicyRuntime(batch_size=1)
    compiled = runtime.compile(_HEADER + "\ndef policy(resource):\n    return resource['ok']\n")
    rows = [{"_subject_id": str(i), "ok": i % 2 == 0} for i in range(5)]
    assert runtime.match_rows(compiled, rows) == [1, 3]


def test_a_fixture_test_that_never_returns_is_killed_at_the_timeout() -> None:
    # Fixture tests used to call policy() in the API process, where a loop
    # hung the request thread for good.
    started = time.monotonic()
    with pytest.raises(FixtureRunError, match=r"timed out|CPU time"):
        _fixture_test(SubprocessPolicyRuntime(timeout_seconds=1), "while True:\n    pass")
    assert time.monotonic() - started < 15


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is only enforced on Linux")
def test_a_policy_that_allocates_without_bound_fails_with_memory_error() -> None:
    runtime = SubprocessPolicyRuntime(memory_budget_mb=256)
    with pytest.raises(FixtureRunError, match="MemoryError"):
        _fixture_test(runtime, "blob = 'a' * (2 * 1024 * 1024 * 1024)\nreturn len(blob) > 0")


def test_the_worker_refuses_an_import() -> None:
    from kestrel.policies.runtime import PolicyCompileError

    with pytest.raises(PolicyCompileError):
        _evaluate(SubprocessPolicyRuntime(), "import os\nreturn True")


def test_the_worker_child_does_not_inherit_the_parents_secrets(monkeypatch) -> None:
    """The real ``subprocess.run`` call carries an allowlisted ``env``.

    RestrictedPython blocks ``os`` in policy code, so a policy cannot read its
    own environment to prove this; instead capture the call the runtime makes.
    """
    import subprocess

    monkeypatch.setenv("KESTREL_MASTER_KEY", "dGVzdC1tYXN0ZXIta2V5LWZvci1jaS1vbmx5ISEhISE=")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kestrel:pw@db/kestrel")
    monkeypatch.setenv("REDIS_URL", "redis://redis:6379/0")
    seen: dict[str, object] = {}
    real_run = subprocess.run

    def capture(*args, **kwargs):
        seen.update(kwargs)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", capture)
    result = _evaluate(SubprocessPolicyRuntime(), "return True")

    assert result.evaluated_row_count == 2  # the child still ran and answered
    env = seen["env"]
    assert isinstance(env, dict)
    assert "KESTREL_MASTER_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "REDIS_URL" not in env
    assert not any(name.startswith("KESTREL_") for name in env)


def test_augmented_assignment_works_in_the_worker() -> None:
    result = _evaluate(SubprocessPolicyRuntime(), "count = 0\nfor _ in range(3):\n    count += 1\nreturn count != 3")
    assert len(result.matches) == 2
