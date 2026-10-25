# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Compiling a policy never runs unbounded author code.

Compilation executes the module body in the *calling* process -- the API, for
validate, fixture test, dry run and generate -- with no timeout or memory
limit. So the module body may only declare constants and functions; anything
that could loop or allocate without bound is a validation error, raised before
any code runs. (Logic inside `policy()` runs under the runtime; the subprocess
runtime's timeout and memory cap are exercised in
`tests/integration/test_policy_runtime_subprocess.py`.)
"""

from __future__ import annotations

import time

import pytest
from kestrel.policies.authoring import parse_policy_source
from kestrel.policies.loader import load_policy_file
from kestrel.policies.runtime import (
    PolicyCompileError,
    RestrictedPythonRuntime,
    SubprocessPolicyRuntime,
    compile_and_validate,
)

_HEADER = 'POLICY_ID = "limits-probe"\nSEVERITY = "low"\n'
_POLICY = "\ndef policy(resource):\n    return True\n"

_REJECTED = {
    "infinite_loop": "while True:\n    pass\n",
    "huge_string": "x = 'a' * (300 * 1024 * 1024)\n",
    "huge_list": "x = [0] * 10**9\n",
    "power": "x = 10 ** 10 ** 10\n",
    "range_call": "x = list(range(10**10))\n",
    "comprehension": "x = [i for i in range(10**9)]\n",
    "for_loop": "for i in range(10**9):\n    pass\n",
    "if_statement": "if True:\n    x = 1\n",
    "try_statement": "try:\n    x = 1\nexcept Exception:\n    pass\n",
    "bare_call": "len('x')\n",
    "class_body": "class A:\n    while True:\n        pass\n",
    "decorator": "def deco(f):\n    return f\n@deco\ndef g():\n    pass\n",
    "default_argument": "def g(x='a' * 10**9):\n    pass\n",
    "annotation_call": "def g(x: len('abc')):\n    pass\n",
    "lambda_value": "x = lambda: 1\n",
    "fstring_value": "x = f'{1}'\n",
    "attribute_target": "time.sleep = len\n",
    "walrus": "(x := 1)\n",
    # Each tuple holds the previous one twice: a few lines describe 2**60 nodes,
    # and hashing them (set elements, dict keys, frozenset()) never finishes.
    "hashed_reference_chain_set": "L0 = (1,)\n"
    + "".join(f"L{i} = (L{i - 1}, L{i - 1})\n" for i in range(1, 61))
    + "X = {L60}\n",
    "hashed_reference_dict_key": "L0 = (1,)\nL1 = (L0, L0)\nX = {L1: 1}\n",
    "hashed_reference_frozenset": "L0 = (1,)\nX = frozenset((L0,))\n",
}


@pytest.mark.parametrize("snippet", _REJECTED.values(), ids=_REJECTED.keys())
def test_module_level_code_that_could_run_unbounded_is_a_compile_error(snippet: str) -> None:
    started = time.monotonic()
    with pytest.raises(PolicyCompileError) as excinfo:
        compile_and_validate(_HEADER + snippet + _POLICY)
    assert time.monotonic() - started < 1
    assert excinfo.value.line is not None
    assert "put logic inside policy()" in str(excinfo.value)


_ALLOWED = {
    "docstring": '"""A policy."""\n',
    "constants": "A = 1\nB = -2.5\nC = 'x'\nD = None\nE = True\n",
    "containers": "A = ('a', 'b')\nB = ['a']\nC = {'a': [1, 2]}\nD = {'a', 'b'}\n",
    "numeric_arithmetic": "MAX_SESSION_MINUTES = 12 * 60\nX = (1 + 2) // 3 - 4 % 5\n",
    "frozenset_literal": "ROLES = frozenset({'admin', 'owner'})\nEMPTY = tuple()\n",
    "name_alias": "A = 1\nB = A\n",
    "plain_function": "def helper(value, days=90, *, strict=False):\n    while True:\n        return value\n",
    "simple_annotations": "def helper(value: str | None, items: list[str]) -> bool:\n    return True\n",
}


@pytest.mark.parametrize("snippet", _ALLOWED.values(), ids=_ALLOWED.keys())
def test_declarative_module_level_code_still_compiles(snippet: str) -> None:
    compile_and_validate(_HEADER + snippet + _POLICY)


_LOOP_SOURCE = _HEADER + "while True:\n    pass\n" + _POLICY


def test_every_compile_entry_point_rejects_a_module_level_loop(tmp_path) -> None:
    with pytest.raises(PolicyCompileError):
        RestrictedPythonRuntime().compile(_LOOP_SOURCE)
    with pytest.raises(PolicyCompileError):
        SubprocessPolicyRuntime().compile(_LOOP_SOURCE)

    parsed = parse_policy_source(_LOOP_SOURCE)
    assert not parsed.is_valid
    assert any("put logic inside policy()" in str(error) for error in parsed.errors)

    path = tmp_path / "loop.py"
    path.write_text(_LOOP_SOURCE)
    loaded = load_policy_file(path)
    assert not loaded.is_valid


def test_the_pack_runtime_setting_never_applies_to_custom_policies(monkeypatch):
    from kestrel.policies.runtime import factory

    monkeypatch.setenv("KESTREL_POLICY_RUNTIME", "subprocess")
    monkeypatch.setenv("KESTREL_PACK_POLICY_RUNTIME", "restricted")
    factory.reset_default_runtime()
    try:
        assert type(factory.get_trusted_runtime()).__name__ == "RestrictedPythonRuntime"
        assert type(factory.get_default_runtime()).__name__ == "SubprocessPolicyRuntime"
    finally:
        factory.reset_default_runtime()


def test_names_stay_allowed_where_nothing_is_hashed() -> None:
    compiled = compile_and_validate(_HEADER + "BASE = ('a', 'b')\nALL = [BASE, BASE]\nBY_NAME = {'x': BASE}\n" + _POLICY)
    assert compiled.contract.policy_id == "limits-probe"


@pytest.mark.parametrize(
    "body",
    [
        "tuple = hash\nX = tuple((1, 2))\n",
        "frozenset = repr\nX = frozenset(L)\n",
        "def tuple(x):\n    return x\nX = tuple((1,))\n",
        "within_last_days = len\n",
        "time = None\n",
        "_getattr_ = None\n",
    ],
    ids=["rebind_tuple", "rebind_frozenset", "shadow_with_function", "rebind_helper", "rebind_time", "rebind_guard"],
)
def test_module_body_cannot_rebind_builtins_or_helpers(body: str) -> None:
    """``tuple = hash`` then ``X = tuple(L40)`` would hash an exponentially nested
    literal at compile time, in the API process. The names the static-value
    check trusts are not rebindable."""
    with pytest.raises(PolicyCompileError, match=r"must not (rebind|shadow)"):
        RestrictedPythonRuntime().compile(_HEADER + "L = (1, 2)\n" + body + _POLICY)


def test_module_body_may_still_bind_ordinary_names() -> None:
    compiled = RestrictedPythonRuntime().compile(_HEADER + "ADMINS = frozenset({'a'})\nLIMIT = 12 * 60\n" + _POLICY)
    assert compiled.contract.policy_id == "limits-probe"
