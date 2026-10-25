# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Small fixed RBAC: role ordering is an explicit rank table, not enum
declaration order, so it stays correct regardless of how OperatorRole's
members are ever reordered."""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole

_ROLE_RANK: dict[OperatorRole, int] = {
    OperatorRole.READ_ONLY: 0,
    OperatorRole.ANALYST: 1,
    OperatorRole.ADMIN: 2,
}


def role_satisfies(actual: OperatorRole, minimum: OperatorRole) -> bool:
    return _ROLE_RANK[actual] >= _ROLE_RANK[minimum]
