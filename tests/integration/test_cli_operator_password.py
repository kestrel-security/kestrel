# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- `kestrel operator set-password` is the break-glass reset after a
compromise, so it ends the operator's sessions and, by default, API tokens,
like the admin reset in the API."""

from __future__ import annotations

from kestrel.auth.service import create_api_token, create_session, lookup_operator_by_bearer_token
from kestrel.cli import operator as operator_cli
from kestrel.testing.factories import make_operator, make_organization
from typer.testing import CliRunner

from tests.integration.test_worker_tasks import _BorrowedSession


def _setup(db_session, monkeypatch):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    _session_row, session_token = create_session(db_session, operator)
    _token_row, api_token = create_api_token(db_session, operator, name="ci")
    db_session.flush()
    monkeypatch.setattr(operator_cli, "get_sessionmaker", lambda: lambda: _BorrowedSession(db_session))
    return operator, session_token, api_token


def test_set_password_revokes_sessions_and_api_tokens(db_session, monkeypatch):
    operator, session_token, api_token = _setup(db_session, monkeypatch)

    result = CliRunner().invoke(operator_cli.app, ["set-password", operator.email])

    assert result.exit_code == 0, result.output
    assert lookup_operator_by_bearer_token(db_session, session_token) is None
    assert lookup_operator_by_bearer_token(db_session, api_token) is None


def test_set_password_can_keep_api_tokens(db_session, monkeypatch):
    operator, session_token, api_token = _setup(db_session, monkeypatch)

    result = CliRunner().invoke(operator_cli.app, ["set-password", operator.email, "--keep-api-tokens"])

    assert result.exit_code == 0, result.output
    assert lookup_operator_by_bearer_token(db_session, session_token) is None
    assert lookup_operator_by_bearer_token(db_session, api_token) is not None


def test_reset_mfa_removes_the_authenticator_and_sessions(db_session, monkeypatch):
    from kestrel.auth import mfa

    operator, session_token, _api_token = _setup(db_session, monkeypatch)
    mfa.start_enrolment(operator)
    operator.mfa_enabled_at = operator.updated_at
    db_session.flush()
    assert mfa.is_enrolled(operator)

    result = CliRunner().invoke(operator_cli.app, ["reset-mfa", operator.email])

    assert result.exit_code == 0, result.output
    db_session.refresh(operator)
    assert not mfa.is_enrolled(operator)
    assert lookup_operator_by_bearer_token(db_session, session_token) is None
