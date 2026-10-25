# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The RestrictedPython sandbox refuses the classic escape routes.

Each case is policy source that, if the sandbox let it through, would reach
the interpreter, the filesystem, or a process. "Refused" means one of two
things, and both are acceptable: compilation fails (`PolicyCompileError`), or
the policy compiles but raises when the row is evaluated. What must never
happen is a policy returning normally after the attempt.

The infinite-loop case needs a child process and so lives in the integration
tier (`tests/integration/test_policy_runtime_subprocess.py`).
"""

from __future__ import annotations

import time
import uuid

import pytest
from kestrel.policies.runtime import PolicyCompileError, RestrictedPythonRuntime, worker
from kestrel.policies.runtime.serialize import rows_to_jsonable

_HEADER = 'POLICY_ID = "sandbox-probe"\nSEVERITY = "low"\n'


def _policy(body: str) -> str:
    indented = "\n".join(f"    {line}" for line in body.strip().splitlines())
    return f"{_HEADER}\ndef policy(resource):\n{indented}\n    return True\n"


def _assert_refused(source: str) -> None:
    runtime = RestrictedPythonRuntime()
    try:
        compiled = runtime.compile(source)
    except PolicyCompileError:
        return
    # Any exception is a refusal; returning normally is the failure.
    try:
        compiled.policy_fn({"_subject_id": "s1", "identity": {}})
    except Exception:  # noqa: BLE001 -- the sandbox may refuse with any error type
        return
    pytest.fail("policy returned normally after an escape attempt")


_MODULE_LEVEL_ESCAPES = {
    "import_os": "import os\n",
    "import_subprocess": "import subprocess\n",
    "from_import": "from os import system\n",
    "dunder_import": '__import__("os")\n',
    "importlib_via_builtins": '__builtins__["__import__"]("os")\n',
}


@pytest.mark.parametrize("snippet", _MODULE_LEVEL_ESCAPES.values(), ids=_MODULE_LEVEL_ESCAPES.keys())
def test_module_level_import_attempts_are_refused(snippet: str) -> None:
    source = _HEADER + snippet + "\ndef policy(resource):\n    return True\n"
    with pytest.raises(PolicyCompileError):
        RestrictedPythonRuntime().compile(source)


_ESCAPES = {
    "import_inside_policy": "import os",
    "open_file": 'open("/etc/passwd").read()',
    "exec": 'exec("x = 1")',
    "eval": 'eval("1")',
    "compile_builtin": 'compile("1", "x", "eval")',
    "builtins_name": "b = __builtins__",
    "builtins_via_globals": 'globals()["__builtins__"]',
    "vars_builtin": "vars()",
    "locals_builtin": "locals()",
    "type_builtin": "type(resource)",
    "class_attr": "c = resource.__class__",
    "subclasses": "().__class__.__bases__[0].__subclasses__()",
    "mro_then_subclasses": "PolicyDataError.mro()[-1].__subclasses__()",
    "getattr_builtin": 'getattr(resource, "__class__")',
    "guard_called_directly": '_getattr_(resource, "__class__")',
    "getattr_via_string_concat": 'getattr(resource, "__cl" + "ass__")',
    "str_format_traversal": '"{0.__class__}".format(resource)',
    "str_format_map_traversal": '"{x.__class__}".format_map({"x": resource})',
    "fstring_dunder": 'f"{resource.__class__}"',
    "function_globals": "within_last_days.__globals__",
    "function_code": "within_last_days.__code__",
    "generator_frame": "(x for x in [1]).gi_frame.f_globals",
    "generator_frame_builtins": "(x for x in [1]).gi_frame.f_builtins",
    "traceback_frame": "try:\n    1 / 0\nexcept Exception as exc:\n    exc.__traceback__.tb_frame",
    "time_module_loader": "time.__loader__",
    "time_module_spec": "time.__spec__",
    "monkeypatch_time": "time.time = len",
    "setattr_on_module": 'setattr(time, "time", len)',
    "delattr_on_module": 'delattr(time, "sleep")',
    "monkeypatch_helper": "within_last_days.cache = 1",
}


@pytest.mark.parametrize("body", _ESCAPES.values(), ids=_ESCAPES.keys())
def test_escape_attempt_is_refused(body: str) -> None:
    _assert_refused(_policy(body))


def test_a_refused_monkeypatch_leaves_the_real_time_module_alone() -> None:
    # `time` is the host's real module object. If a write guard ever loosened,
    # an in-process policy could rebind it for every other policy (and the
    # host). The probe above proves the write raises; this proves nothing
    # leaked through regardless.
    before = time.time
    _assert_refused(_policy("time.time = len"))
    assert time.time is before


def test_the_probe_harness_would_notice_an_escape() -> None:
    # Guard against a vacuous suite: a body that the sandbox allows must make
    # `_assert_refused` fail, or every case above could be passing for free.
    with pytest.raises(pytest.fail.Exception):
        _assert_refused(_policy("x = len(resource)"))


# ---------------------------------------------------------------------------
# Row isolation. A policy may write to the dict it is handed (item assignment
# is allowed so policies can build local structures), so the runtime must hand
# it a copy: rows are shared by every policy in a pass (RowCache), and the
# match's subject is read back after policy() returns.
# ---------------------------------------------------------------------------

_TAMPER_SOURCE = """
POLICY_ID = "tamper"
SEVERITY = "low"

def policy(resource):
    resource["identity"]["mfa_enabled"] = True
    resource["_subject_id"] = "00000000-0000-0000-0000-000000000000"
    return False
"""

_MFA_SOURCE = """
POLICY_ID = "mfa"
SEVERITY = "high"

def policy(resource):
    return bool(resource["identity"]["mfa_enabled"])
"""

_SUBJECT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _identity_row() -> dict:
    return {"_subject_id": _SUBJECT, "_subject_type": "identity", "identity": {"mfa_enabled": False}}


def test_in_process_policy_cannot_rewrite_rows_for_the_next_policy() -> None:
    runtime = RestrictedPythonRuntime()
    rows = [_identity_row()]
    org_id = uuid.uuid4()

    # `session` is only used to load rows, and rows are passed in.
    tampered = runtime.evaluate_all(runtime.compile(_TAMPER_SOURCE), None, org_id, rows=rows)  # type: ignore[arg-type]
    checked = runtime.evaluate_all(runtime.compile(_MFA_SOURCE), None, org_id, rows=rows)  # type: ignore[arg-type]

    assert rows[0]["identity"]["mfa_enabled"] is False
    assert [m.subject_id for m in tampered.matches] == [_SUBJECT]
    assert [m.subject_id for m in checked.matches] == [_SUBJECT]


def test_worker_policy_cannot_retarget_the_finding_subject() -> None:
    result = worker._run({"source_text": _TAMPER_SOURCE, "rows": rows_to_jsonable([_identity_row()])})

    assert result["ok"] is True
    assert [m["subject_id"] for m in result["matches"]] == [str(_SUBJECT)]


# ---------------------------------------------------------------------------
# Augmented assignment. RestrictedPython rewrites `x += 1` into a call to
# `_inplacevar_`, which the host must supply; without it every such policy
# compiled fine and then raised NameError on its first row. A policy returning
# False is a match.
# ---------------------------------------------------------------------------

_COUNTING_SOURCE = """
POLICY_ID = "counting"
SEVERITY = "low"

def policy(resource):
    count = 0
    for grant in resource["identity"]["grants"]:
        count += 1
    label = "n="
    label += str(count)
    return count < 2 and label == "n=" + str(count)
"""


def _counting_row(grants: int) -> dict:
    return {"_subject_id": _SUBJECT, "_subject_type": "identity", "identity": {"grants": ["g"] * grants}}


@pytest.mark.parametrize(("grants", "matched"), [(2, True), (1, False)])
def test_in_process_policy_can_use_augmented_assignment(grants: int, matched: bool) -> None:
    runtime = RestrictedPythonRuntime()
    compiled = runtime.compile(_COUNTING_SOURCE)
    result = runtime.evaluate_all(compiled, None, uuid.uuid4(), rows=[_counting_row(grants)])  # type: ignore[arg-type]

    assert [m.subject_id for m in result.matches] == ([_SUBJECT] if matched else [])


def test_worker_policy_can_use_augmented_assignment() -> None:
    result = worker._run({"source_text": _COUNTING_SOURCE, "rows": rows_to_jsonable([_counting_row(3)])})

    assert result["ok"] is True, result
    assert [m["subject_id"] for m in result["matches"]] == [str(_SUBJECT)]


def test_inplacevar_refuses_an_unknown_operator() -> None:
    from kestrel.policies.runtime.restricted import _inplacevar

    assert _inplacevar("*=", [1], 2) == [1, 1]
    with pytest.raises(SyntaxError):
        _inplacevar("and=", 1, 2)
