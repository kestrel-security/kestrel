# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Subprocess-isolated policy evaluation.

Compiles/validates in-process with RestrictedPython (fast author feedback),
then evaluates rows in a short-lived child process so policy code cannot
mutate API/worker memory, open sockets, or hang the parent indefinitely.

Large row sets are evaluated in batches so each child stays under
``KESTREL_POLICY_EVAL_TIMEOUT_SECONDS``; batch match results are merged.
"""

from __future__ import annotations

import json
import logging
import math
import os
import signal
import subprocess
import sys
import time
import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.env import getenv_str
from kestrel.policies.dataload import load_rows
from kestrel.policies.runtime.restricted import (
    RestrictedPythonRuntime,
    _from_type_for_resource_type,
    attach_related_grants,
)
from kestrel.policies.runtime.serialize import rows_to_jsonable
from kestrel.policies.runtime.types import (
    CompiledPolicy,
    PolicyEvaluationResult,
    PolicyMatch,
)

logger = logging.getLogger(__name__)

DEFAULT_EVAL_TIMEOUT_SECONDS = 30.0
DEFAULT_EVAL_BATCH_SIZE = 2000
# Memory a worker may allocate beyond what the interpreter and imports use.
DEFAULT_EVAL_MEMORY_MB = 512
_ENV_TIMEOUT = "KESTREL_POLICY_EVAL_TIMEOUT_SECONDS"
_ENV_BATCH_SIZE = "KESTREL_POLICY_EVAL_BATCH_SIZE"
_ENV_MEMORY_MB = "KESTREL_POLICY_EVAL_MEMORY_MB"


# Environment variables the worker child is allowed to see. Everything else --
# in particular KESTREL_MASTER_KEY, DATABASE_URL, REDIS_URL, and any provider
# credential -- stays in the parent, so a RestrictedPython escape in policy
# code does not hand the attacker the key that decrypts every stored secret.
_WORKER_ENV_PASSTHROUGH = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TMP",
        "TEMP",
        # Interpreter location in editable installs and virtualenvs.
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "PYTHONHOME",
        # Windows cannot start a process without these.
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
    }
)


def worker_environment(parent: dict[str, str] | None = None) -> dict[str, str]:
    """Build the minimal environment the policy worker child runs with.

    Only the allowlisted interpreter/locale variables pass through from
    ``parent`` (``os.environ`` by default); no ``KESTREL_*`` or connection
    strings do. The child never needs them: it only imports
    ``kestrel.policies.runtime`` and reads its payload from stdin.
    """
    source = os.environ if parent is None else parent
    env = {name: value for name, value in source.items() if name in _WORKER_ENV_PASSTHROUGH}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _parse_positive_int(raw: str, *, env_name: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{env_name} must be a positive integer, got {raw!r}") from exc
    if value < 1:
        raise ValueError(f"{env_name} must be >= 1, got {value}")
    return value


class SubprocessPolicyRuntime:
    """PolicyRuntime that evaluates matches in an isolated Python subprocess."""

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        batch_size: int | None = None,
        python_executable: str | None = None,
        memory_budget_mb: int | None = None,
    ) -> None:
        if timeout_seconds is None:
            raw = getenv_str(_ENV_TIMEOUT, "").strip()
            timeout_seconds = float(raw) if raw else DEFAULT_EVAL_TIMEOUT_SECONDS
        self.timeout_seconds = max(1.0, float(timeout_seconds))

        if batch_size is None:
            raw_batch = getenv_str(_ENV_BATCH_SIZE, "").strip()
            batch_size = _parse_positive_int(raw_batch, env_name=_ENV_BATCH_SIZE) if raw_batch else DEFAULT_EVAL_BATCH_SIZE
        if batch_size < 1:
            raise ValueError(f"batch_size must be >= 1, got {batch_size}")
        self.batch_size = int(batch_size)

        if memory_budget_mb is None:
            raw_memory = getenv_str(_ENV_MEMORY_MB, "").strip()
            memory_budget_mb = int(raw_memory) if raw_memory else DEFAULT_EVAL_MEMORY_MB
        # 0 disables the cap. Enforced via RLIMIT_AS where the OS supports it (Linux).
        self.memory_budget_bytes = max(0, int(memory_budget_mb)) * 1024 * 1024

        self.python_executable = python_executable or sys.executable
        self._compiler = RestrictedPythonRuntime()

    def compile(self, source_text: str) -> CompiledPolicy:
        # Validate contract + RestrictedPython constraints in-process.
        return self._compiler.compile(source_text)

    def evaluate_all(
        self,
        compiled: CompiledPolicy,
        session: Session,
        org_id: uuid.UUID,
        rows: list[dict[str, Any]] | None = None,
    ) -> PolicyEvaluationResult:
        if rows is None:
            from_type = _from_type_for_resource_type(compiled.contract.resource_type)
            rows = load_rows(session, org_id, from_type)
            if from_type == "identities":
                attach_related_grants(session, org_id, rows)
        return self._evaluate_rows(compiled.source_text, rows, policy_name=compiled.contract.policy_id)

    def _evaluate_rows(
        self,
        source_text: str,
        rows: list[dict[str, Any]],
        *,
        policy_name: str,
    ) -> PolicyEvaluationResult:
        if not rows:
            return PolicyEvaluationResult(
                policy_name=policy_name,
                matches=[],
                evaluated_row_count=0,
            )

        all_matches: list[PolicyMatch] = []
        total_evaluated = 0
        resolved_name = policy_name
        # Every batch judges its rows against the same instant.
        now = time.time()

        for start in range(0, len(rows), self.batch_size):
            batch = rows[start : start + self.batch_size]
            batch_result = self._evaluate_batch(
                source_text,
                batch,
                policy_name=policy_name,
                now=now,
            )
            all_matches.extend(batch_result.matches)
            total_evaluated += batch_result.evaluated_row_count
            resolved_name = batch_result.policy_name

        return PolicyEvaluationResult(
            policy_name=resolved_name,
            matches=all_matches,
            evaluated_row_count=total_evaluated,
        )

    def _evaluate_batch(
        self,
        source_text: str,
        rows: list[dict[str, Any]],
        *,
        policy_name: str,
        now: float,
    ) -> PolicyEvaluationResult:
        result = self._run_worker(
            {"source_text": source_text, "rows": rows_to_jsonable(rows), "now": now},
            policy_name=policy_name,
        )

        matches: list[PolicyMatch] = []
        for item in result.get("matches") or []:
            if not isinstance(item, dict):
                continue
            subject_type = item.get("subject_type")
            subject_id_raw = item.get("subject_id")
            if not isinstance(subject_type, str) or not isinstance(subject_id_raw, str):
                continue
            try:
                subject_id = uuid.UUID(subject_id_raw)
            except ValueError:
                logger.warning("Skipping match with invalid subject_id=%r", subject_id_raw)
                continue
            raw_evidence = item.get("evidence")
            evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
            matches.append(PolicyMatch(subject_type=subject_type, subject_id=subject_id, evidence=evidence))

        return PolicyEvaluationResult(
            policy_name=str(result.get("policy_name") or policy_name),
            matches=matches,
            evaluated_row_count=int(result.get("evaluated_row_count") or len(rows)),
        )

    def match_rows(
        self,
        compiled: CompiledPolicy,
        rows: list[dict[str, Any]],
        *,
        now: float | None = None,
    ) -> list[int]:
        policy_name = compiled.contract.policy_id
        pinned = time.time() if now is None else float(now)
        matched: list[int] = []
        for start in range(0, len(rows), self.batch_size):
            batch = rows[start : start + self.batch_size]
            result = self._run_worker(
                {
                    "source_text": compiled.source_text,
                    "rows": rows_to_jsonable(batch),
                    "mode": "match_rows",
                    "now": pinned,
                },
                policy_name=policy_name,
            )
            matched.extend(start + int(index) for index in result.get("matched_indices") or [])
        return matched

    def _run_worker(self, payload: dict[str, Any], *, policy_name: str) -> dict[str, Any]:
        """Run one worker child and return its ``ok`` result, or raise."""
        payload = {
            **payload,
            "limits": {
                # The child dies of SIGXCPU just after the parent's wall-clock
                # timeout would have fired, so a spinning policy is bounded even
                # if the parent itself is stalled.
                "cpu_seconds": math.ceil(self.timeout_seconds) + 1,
                "memory_bytes": self.memory_budget_bytes,
            },
        }
        try:
            completed = subprocess.run(
                [self.python_executable, "-m", "kestrel.policies.runtime.worker"],
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                env=worker_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Policy evaluation timed out after {self.timeout_seconds:.0f}s (policy={policy_name!r})"
            ) from exc

        if completed.returncode == -signal.SIGXCPU:
            raise TimeoutError(f"Policy evaluation exceeded its CPU time limit (policy={policy_name!r})")
        if completed.returncode != 0 and not completed.stdout:
            stderr = completed.stderr.decode("utf-8", errors="replace")[:2000]
            raise RuntimeError(f"Policy worker failed (exit {completed.returncode}) for {policy_name!r}: {stderr}")

        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            stderr = completed.stderr.decode("utf-8", errors="replace")[:1000]
            raise RuntimeError(f"Policy worker returned invalid JSON for {policy_name!r}: {exc}; stderr={stderr!r}") from exc

        if not isinstance(result, dict) or not result.get("ok"):
            error = result.get("error") if isinstance(result, dict) else "unknown worker error"
            raise RuntimeError(f"Policy worker error for {policy_name!r}: {error}")
        return result
