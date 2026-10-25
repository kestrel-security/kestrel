# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- the system policies that own toxic-combination findings must be
valid policies: the policy page, test, and dry run all compile them."""

from __future__ import annotations

from kestrel.db.models.policy import Severity
from kestrel.findings.toxic_combo import _system_source_text
from kestrel.policies.runtime.factory import compile_and_validate


def test_system_toxic_policy_compiles_and_never_matches():
    source = _system_source_text(
        slug="system-toxic-example",
        title='Admin "without" MFA',
        description="It's an attack path",
        severity=Severity.CRITICAL,
        remediation="Fix both findings.",
    )

    compiled = compile_and_validate(source)

    assert compiled.contract.policy_id == "system-toxic-example"
    assert compiled.contract.severity == "critical"
    assert compiled.policy_fn({"identity": {}}) is True
