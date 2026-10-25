# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Subprocess worker: evaluate one policy source against JSON rows.

Invoked as ``python -m kestrel.policies.runtime.worker``. Reads a single JSON
object from stdin and writes a single JSON object to stdout. Used by
``SubprocessPolicyRuntime`` so policy code never runs in the API/worker
process address space.

The parent enforces a wall-clock timeout; the child also caps its own CPU time
and memory (``limits`` in the payload) before it compiles anything, so a
policy that spins or allocates without bound dies here instead of starving the
host.
"""

from __future__ import annotations

import contextlib
import copy
import json
import sys
import traceback
from typing import Any

from kestrel.policies.evidence_baseline import merge_baseline_evidence
from kestrel.policies.runtime.restricted import RestrictedPythonRuntime
from kestrel.policies.runtime.serialize import row_from_jsonable, row_to_jsonable
from kestrel.policies.runtime.types import PolicyCompileError

try:  # POSIX only; elsewhere the parent's wall-clock timeout is the only limit.
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]


def _current_address_space_bytes() -> int | None:
    """Virtual memory already mapped (Linux), so the memory budget is added on
    top of what the interpreter and its imports already use."""
    if resource is None:
        return None
    try:
        with open("/proc/self/statm") as statm:
            pages = int(statm.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    return pages * resource.getpagesize()


def _lower_limit(which: int, soft: int) -> None:
    assert resource is not None
    _, hard = resource.getrlimit(which)
    if hard != resource.RLIM_INFINITY:
        soft = min(soft, hard)
    # macOS, for one, refuses RLIMIT_AS. The wall-clock timeout still holds.
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(which, (soft, hard))


def _apply_limits(limits: Any) -> None:
    if resource is None or not isinstance(limits, dict):
        return
    cpu_seconds = limits.get("cpu_seconds")
    if isinstance(cpu_seconds, int) and cpu_seconds > 0:
        _lower_limit(resource.RLIMIT_CPU, cpu_seconds)
    memory_bytes = limits.get("memory_bytes")
    if isinstance(memory_bytes, int) and memory_bytes > 0:
        baseline = _current_address_space_bytes()
        if baseline is not None:
            _lower_limit(resource.RLIMIT_AS, baseline + memory_bytes)


def _run(payload: dict[str, Any]) -> dict[str, Any]:
    source_text = payload.get("source_text")
    if not isinstance(source_text, str) or not source_text.strip():
        return {"ok": False, "error": "source_text is required"}
    raw_rows = payload.get("rows")
    if not isinstance(raw_rows, list):
        return {"ok": False, "error": "rows must be a list"}
    # "evaluate" (default) returns matches with evidence; "match_rows" returns
    # only the indices of non-compliant rows (fixture tests, fixture capture).
    match_rows_only = payload.get("mode") == "match_rows"

    runtime = RestrictedPythonRuntime()
    try:
        compiled = runtime.compile(source_text)
    except PolicyCompileError as exc:
        return {"ok": False, "error": str(exc)}

    matches: list[dict[str, Any]] = []
    matched_indices: list[int] = []
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            return {"ok": False, "error": "each row must be an object"}
        row = row_from_jsonable(raw)
        # The subject and baseline evidence come from ``row``; the policy only
        # ever sees ``visible``, so writing to its argument cannot retarget a
        # finding at another subject.
        visible = copy.deepcopy(row)
        try:
            compliant = compiled.policy_fn(visible)
        except Exception as exc:  # noqa: BLE001 -- policy code can raise anything; reported to the parent
            return {
                "ok": False,
                "error": f"policy() raised {type(exc).__name__} on subject {row.get('_subject_id')}: {exc}",
            }
        if not isinstance(compliant, bool):
            return {
                "ok": False,
                "error": f"policy() must return bool, got {type(compliant).__name__}",
            }
        if compliant:
            continue
        if match_rows_only:
            matched_indices.append(index)
            continue
        evidence: dict[str, Any] = {}
        if compiled.evidence_fn is not None:
            try:
                evidence = compiled.evidence_fn(visible)
            except Exception as exc:  # noqa: BLE001 -- policy code can raise anything; reported to the parent
                return {
                    "ok": False,
                    "error": f"evidence() raised {type(exc).__name__}: {exc}",
                }
            if not isinstance(evidence, dict):
                return {
                    "ok": False,
                    "error": f"evidence() must return dict, got {type(evidence).__name__}",
                }
        evidence = merge_baseline_evidence(compiled.contract.resource_type, row, evidence)
        matches.append(
            {
                "subject_type": row.get("_subject_type"),
                "subject_id": str(row.get("_subject_id")),
                "evidence": row_to_jsonable(evidence),
            }
        )

    if match_rows_only:
        return {"ok": True, "policy_name": compiled.contract.policy_id, "matched_indices": matched_indices}
    return {
        "ok": True,
        "policy_name": compiled.contract.policy_id,
        "evaluated_row_count": len(raw_rows),
        "matches": matches,
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        json.dump({"ok": False, "error": f"invalid JSON stdin: {exc}"}, sys.stdout)
        return 1
    if not isinstance(payload, dict):
        json.dump({"ok": False, "error": "stdin JSON must be an object"}, sys.stdout)
        return 1
    _apply_limits(payload.get("limits"))
    try:
        result = _run(payload)
    except Exception as exc:  # noqa: BLE001 -- worker top level: report any crash, with traceback, to the parent
        json.dump(
            {
                "ok": False,
                "error": f"worker crash: {type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            },
            sys.stdout,
        )
        return 1
    json.dump(result, sys.stdout)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
