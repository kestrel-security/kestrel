# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy runtime protocol."""

from __future__ import annotations

import uuid
from typing import Any, Protocol

from sqlalchemy.orm import Session

from kestrel.policies.runtime.types import CompiledPolicy, PolicyEvaluationResult


class PolicyRuntime(Protocol):
    def compile(self, source_text: str) -> CompiledPolicy:
        """Parse, validate, and compile policy source into a callable bundle."""
        ...

    def evaluate_all(
        self,
        compiled: CompiledPolicy,
        session: Session,
        org_id: uuid.UUID,
        rows: list[dict[str, Any]] | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate every row of the policy's resource type.

        ``rows`` lets a caller evaluating many policies in one pass load each
        row family once and share it; omitted, the runtime loads them itself.
        """
        ...

    def match_rows(self, compiled: CompiledPolicy, rows: list[dict[str, Any]]) -> list[int]:
        """Indices of the ``rows`` that ``policy()`` reports non-compliant.

        For callers that have rows in hand (fixture tests, fixture capture) and
        must still run author code under this runtime's isolation and limits
        rather than calling ``compiled.policy_fn`` in their own process.
        """
        ...
