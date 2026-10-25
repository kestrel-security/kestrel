# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.auth.rbac.role_satisfies`: the fixed READ_ONLY < ANALYST < ADMIN
hierarchy. The rank table is explicit rather than enum declaration order
(see the module docstring), so these tests pin the *ordering*, not just
individual pairs.
"""

from __future__ import annotations

import itertools

from kestrel.auth.rbac import role_satisfies
from kestrel.db.models.operator import OperatorRole

_ORDERED = (OperatorRole.READ_ONLY, OperatorRole.ANALYST, OperatorRole.ADMIN)


def test_every_role_satisfies_itself():
    for role in OperatorRole:
        assert role_satisfies(role, role) is True


def test_every_role_satisfies_read_only():
    for role in OperatorRole:
        assert role_satisfies(role, OperatorRole.READ_ONLY) is True


def test_read_only_does_not_satisfy_higher_roles():
    assert role_satisfies(OperatorRole.READ_ONLY, OperatorRole.ANALYST) is False
    assert role_satisfies(OperatorRole.READ_ONLY, OperatorRole.ADMIN) is False


def test_analyst_satisfies_analyst_but_not_admin():
    assert role_satisfies(OperatorRole.ANALYST, OperatorRole.ANALYST) is True
    assert role_satisfies(OperatorRole.ANALYST, OperatorRole.ADMIN) is False


def test_admin_satisfies_every_minimum():
    for minimum in OperatorRole:
        assert role_satisfies(OperatorRole.ADMIN, minimum) is True


def test_the_hierarchy_is_strictly_increasing():
    for lower, higher in itertools.combinations(_ORDERED, 2):
        assert role_satisfies(lower, higher) is False
        assert role_satisfies(higher, lower) is True
