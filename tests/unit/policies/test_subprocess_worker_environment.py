# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The policy worker child never inherits the parent's secrets.

Policy code is operator- or AI-written RestrictedPython. If it ever escaped the
sandbox, the child's environment is the first thing it would read, so the
parent hands it an allowlist of interpreter and locale variables and nothing
else: no ``KESTREL_MASTER_KEY``, no connection strings, no provider tokens.
"""

from __future__ import annotations

import os

from kestrel.policies.runtime.subprocess_runtime import worker_environment

_PARENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/opt/kestrel",
    "LANG": "C.UTF-8",
    "VIRTUAL_ENV": "/app/.venv",
    "PYTHONPATH": "/app/src",
    "KESTREL_MASTER_KEY": "dGVzdA==",
    "KESTREL_MASTER_KEY_PREVIOUS": "b2xk",
    "DATABASE_URL": "postgresql+psycopg://kestrel:pw@db/kestrel",
    "REDIS_URL": "redis://redis:6379/0",
    "KESTREL_POLICY_RUNTIME": "subprocess",
    "GITHUB_TOKEN": "ghp_notarealtokenvalue",
    "AWS_SECRET_ACCESS_KEY": "not-a-real-key",
    "PYTHONDONTWRITEBYTECODE": "",
}


def test_secrets_and_connection_strings_do_not_reach_the_child() -> None:
    env = worker_environment(_PARENT)
    for name in env:
        assert not name.startswith("KESTREL_"), name
    for name in ("DATABASE_URL", "REDIS_URL", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"):
        assert name not in env


def test_interpreter_and_locale_variables_pass_through_unchanged() -> None:
    env = worker_environment(_PARENT)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/opt/kestrel"
    assert env["LANG"] == "C.UTF-8"
    assert env["VIRTUAL_ENV"] == "/app/.venv"
    assert env["PYTHONPATH"] == "/app/src"


def test_the_child_is_told_not_to_write_bytecode_or_load_user_site_packages() -> None:
    env = worker_environment(_PARENT)
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["PYTHONNOUSERSITE"] == "1"
    assert env["PYTHONIOENCODING"] == "utf-8"


def test_the_allowlist_is_exact_not_a_prefix_match() -> None:
    # A variable that merely starts with an allowed name is still dropped.
    env = worker_environment({"PATH": "/bin", "PATHOLOGICAL_SECRET": "x", "HOMEBREW_TOKEN": "y"})
    assert env["PATH"] == "/bin"
    assert "PATHOLOGICAL_SECRET" not in env
    assert "HOMEBREW_TOKEN" not in env


def test_defaults_to_the_live_process_environment(monkeypatch) -> None:
    monkeypatch.setenv("KESTREL_MASTER_KEY", "dGVzdA==")
    monkeypatch.setenv("PATH", os.environ.get("PATH", "/usr/bin"))
    env = worker_environment()
    assert "KESTREL_MASTER_KEY" not in env
    assert env["PATH"] == os.environ["PATH"]
