# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the demo's seeded team accounts cannot be used to sign in on a
deployment.

`kestrel demo up` seeds five operators so assignment queues and pickers have
people in them. In a local checkout they share the dev password; anywhere the
configuration comes from the environment they get no password at all, because
an admin account with a password that is printed in the docs is a back door.
"""

from __future__ import annotations

from kestrel.auth.service import authenticate_operator
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.demo.seed_product import _SEED_OPERATORS, ProductSeedResult, _operators
from kestrel.testing.factories import make_operator, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


def _seeded(db_session: Session, org) -> list[Operator]:
    emails = {email for email, *_ in _SEED_OPERATORS}
    return [op for op in db_session.scalars(select(Operator).where(Operator.org_id == org.id)).all() if op.email in emails]


def test_seeded_team_has_no_password_on_a_deployment(db_session: Session):
    org = make_organization(db_session)
    make_operator(db_session, org)

    _operators(db_session, org, ProductSeedResult(), password=None)

    seeded = _seeded(db_session, org)
    assert len(seeded) == len(_SEED_OPERATORS)
    assert all(op.password_hash is None for op in seeded)
    admin = next(op for op in seeded if op.role == OperatorRole.ADMIN)
    assert authenticate_operator(db_session, org.id, admin.email, "kestrel-dev-password") is None


def test_seeded_team_shares_the_given_password_in_a_checkout(db_session: Session):
    org = make_organization(db_session)
    make_operator(db_session, org)

    _operators(db_session, org, ProductSeedResult(), password="kestrel-dev-password")

    admin = next(op for op in _seeded(db_session, org) if op.role == OperatorRole.ADMIN)
    assert authenticate_operator(db_session, org.id, admin.email, "kestrel-dev-password") is not None
