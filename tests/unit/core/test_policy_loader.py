# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.policies.loader`: discover and compile `.py` policy files from a
directory into `LoadedPolicy` objects, without touching the DB.

All fixtures here are written to `tmp_path` -- nothing is read from a shipped
pack or connector fixture (rule 1 / rule 5 of docs/testing.md).
"""

from __future__ import annotations

from pathlib import Path

from kestrel.policies.loader import LoadedPolicy, load_policy_directory, load_policy_file

_VALID_SOURCE = """
POLICY_ID = "test-tmp-policy"
TITLE = "A policy built entirely by this test"
SEVERITY = "low"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Exercises the loader without touching a shipped pack."

def policy(resource):
    return bool(resource.get("identity", {}).get("mfa_enabled"))
"""

_INVALID_SOURCE = """
TITLE = "Missing POLICY_ID"
SEVERITY = "low"

def policy(resource):
    return True
"""

_UNPARSEABLE_SOURCE = "def policy(resource:\n    return True"


def _write(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / name
    path.write_text(source)
    return path


def test_load_policy_file_compiles_a_valid_policy(tmp_path):
    path = _write(tmp_path, "valid_policy.py", _VALID_SOURCE)

    loaded = load_policy_file(path)

    assert isinstance(loaded, LoadedPolicy)
    assert loaded.is_valid is True
    assert loaded.errors == []
    assert loaded.compiled is not None
    assert loaded.slug == "test-tmp-policy"


def test_load_policy_file_reports_errors_for_invalid_policy_without_raising(tmp_path):
    path = _write(tmp_path, "invalid_policy.py", _INVALID_SOURCE)

    loaded = load_policy_file(path)

    assert loaded.is_valid is False
    assert loaded.compiled is None
    assert loaded.errors
    assert any("POLICY_ID" in message for message in loaded.errors)


def test_load_policy_file_reports_syntax_errors_without_raising(tmp_path):
    path = _write(tmp_path, "unparseable_policy.py", _UNPARSEABLE_SOURCE)

    loaded = load_policy_file(path)

    assert loaded.is_valid is False
    assert loaded.errors


def test_slug_falls_back_to_the_filename_when_the_policy_did_not_compile(tmp_path):
    path = _write(tmp_path, "some_broken_policy.py", _INVALID_SOURCE)

    loaded = load_policy_file(path)

    assert loaded.slug == "some-broken-policy"


def test_load_policy_directory_discovers_every_py_file_sorted(tmp_path):
    _write(tmp_path, "z_policy.py", _VALID_SOURCE.replace("test-tmp-policy", "z-policy"))
    _write(tmp_path, "a_policy.py", _VALID_SOURCE.replace("test-tmp-policy", "a-policy"))

    loaded = load_policy_directory(tmp_path)

    assert [lp.path.name for lp in loaded] == ["a_policy.py", "z_policy.py"]
    assert all(lp.is_valid for lp in loaded)


def test_load_policy_directory_skips_underscore_prefixed_files(tmp_path):
    _write(tmp_path, "_helpers.py", "SHARED_CONSTANT = 1\n")
    _write(tmp_path, "real_policy.py", _VALID_SOURCE)

    loaded = load_policy_directory(tmp_path)

    assert [lp.path.name for lp in loaded] == ["real_policy.py"]


def test_load_policy_directory_of_an_empty_directory_returns_no_policies(tmp_path):
    assert load_policy_directory(tmp_path) == []
