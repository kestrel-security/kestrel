# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Select the active PolicyRuntime implementation."""

from __future__ import annotations

from kestrel.env import getenv_str
from kestrel.policies.runtime.protocol import PolicyRuntime
from kestrel.policies.runtime.restricted import RestrictedPythonRuntime
from kestrel.policies.runtime.subprocess_runtime import SubprocessPolicyRuntime
from kestrel.policies.runtime.types import CompiledPolicy

_ENV_RUNTIME = "KESTREL_POLICY_RUNTIME"
_ENV_TRUSTED_RUNTIME = "KESTREL_PACK_POLICY_RUNTIME"
_default_runtime: PolicyRuntime | None = None
_trusted_runtime: PolicyRuntime | None = None


def get_default_runtime() -> PolicyRuntime:
    """Return the process-wide default runtime.

    ``KESTREL_POLICY_RUNTIME``:
    - ``subprocess`` (default) — compile in-process; evaluate in a child process
    - ``restricted`` / ``inprocess`` — RestrictedPython entirely in-process,
      with no time or memory limit: only for tests and trusted code
    """
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = create_runtime()
    return _default_runtime


def get_trusted_runtime() -> PolicyRuntime:
    """Runtime for first-party pack and system policies only.

    ``KESTREL_PACK_POLICY_RUNTIME`` (default: whatever the default runtime is)
    may select the in-process runtime for that trusted code, which is several
    times faster. It never applies to custom policies: those are operator- or
    AI-authored and always get the default runtime's isolation and limits.
    "Pack" means any pack-sourced policy, including a pack installed from a
    local path with ``kestrel pack install``; only set this when every
    installed pack is one you trust.
    """
    global _trusted_runtime
    if _trusted_runtime is None:
        mode = getenv_str(_ENV_TRUSTED_RUNTIME, "")
        _trusted_runtime = create_runtime(mode) if mode.strip() else get_default_runtime()
    return _trusted_runtime


def create_runtime(mode: str | None = None) -> PolicyRuntime:
    """Build a runtime for ``mode`` (or ``KESTREL_POLICY_RUNTIME`` / subprocess)."""
    raw = (mode if mode is not None else getenv_str(_ENV_RUNTIME, "subprocess")).strip().lower()
    if raw in ("restricted", "inprocess", "in-process"):
        return RestrictedPythonRuntime()
    return SubprocessPolicyRuntime()


def reset_default_runtime() -> None:
    """Clear the cached default (tests)."""
    global _default_runtime, _trusted_runtime
    _default_runtime = None
    _trusted_runtime = None


def compile_and_validate(source_text: str) -> CompiledPolicy:
    """Compile/validate with RestrictedPython (authoring path; no eval)."""
    return RestrictedPythonRuntime().compile(source_text)
