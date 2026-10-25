# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared types for the Python policy runtime."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class PolicyCompileError(Exception):
    """Raised when policy source fails validation or compilation.

    Optional ``line`` / ``column`` (1-based line, 1-based column when known)
    let the Workbench surface parse/compile locations.
    """

    def __init__(
        self,
        message: str,
        *,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.message = message
        self.line = line
        self.column = column
        super().__init__(self.format_message())

    def format_message(self) -> str:
        if self.line is not None and self.column is not None:
            return f"line {self.line}, col {self.column}: {self.message}"
        if self.line is not None:
            return f"line {self.line}: {self.message}"
        return self.message


@dataclass(frozen=True)
class PolicyContract:
    policy_id: str
    title: str
    severity: str
    resource_type: str
    description: str
    remediation: str | None
    compliance: dict[str, list[str]]
    requires: tuple[str, ...] = ()
    profile: str = "level_1"


@dataclass(frozen=True)
class CompiledPolicy:
    contract: PolicyContract
    policy_fn: Callable[[dict[str, Any]], bool]
    evidence_fn: Callable[[dict[str, Any]], dict[str, Any]] | None
    source_text: str


@dataclass
class PolicyMatch:
    subject_type: str
    subject_id: uuid.UUID
    evidence: dict[str, Any]


@dataclass
class PolicyEvaluationResult:
    policy_name: str
    matches: list[PolicyMatch] = field(default_factory=list)
    evaluated_row_count: int = 0
