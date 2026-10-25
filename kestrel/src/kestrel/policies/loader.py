# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Discovers and compiles `.py` policy files from a directory into CompiledPolicy
objects, without touching the DB. Backs `kestrel policy validate` and pack install.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kestrel.policies.runtime import CompiledPolicy, PolicyCompileError, compile_and_validate


@dataclass
class LoadedPolicy:
    path: Path
    source_text: str
    compiled: CompiledPolicy | None
    errors: list[str]

    @property
    def is_valid(self) -> bool:
        return not self.errors and self.compiled is not None

    @property
    def slug(self) -> str:
        if self.compiled is not None:
            return self.compiled.contract.policy_id
        return self.path.stem.replace("_", "-")


def load_policy_file(path: str | Path) -> LoadedPolicy:
    path = Path(path)
    source_text = path.read_text()
    try:
        compiled = compile_and_validate(source_text)
    except PolicyCompileError as exc:
        return LoadedPolicy(path=path, source_text=source_text, compiled=None, errors=[str(exc)])
    return LoadedPolicy(path=path, source_text=source_text, compiled=compiled, errors=[])


def load_policy_directory(directory: str | Path) -> list[LoadedPolicy]:
    directory = Path(directory)
    return [load_policy_file(p) for p in sorted(directory.glob("*.py")) if not p.name.startswith("_")]
