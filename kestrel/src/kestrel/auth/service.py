# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Login, session, and API token lifecycle. Uniform failure behavior for
authenticate_operator (unknown email / wrong password / inactive / locked
all return None, and all run one Argon2 verification so they take the same
time) avoids user enumeration."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from kestrel.auth.mfa import is_enrolled
from kestrel.auth.passwords import burn_password_check, hash_password, needs_rehash, verify_password
from kestrel.auth.tokens import generate_token, hash_token
from kestrel.db.models.operator import (
    MFA_STATE_CHALLENGE,
    MFA_STATE_ENROLL,
    MFA_STATE_VERIFIED,
    ApiToken,
    Operator,
    OperatorSession,
)

LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = timedelta(minutes=15)

SESSION_SLIDING_WINDOW = timedelta(hours=24)
SESSION_ABSOLUTE_LIFETIME = timedelta(days=30)
#: How long a password-verified sign-in may wait for its second factor.
MFA_CHALLENGE_LIFETIME = timedelta(minutes=5)
#: How long a sign-in that must enrol in MFA first may take to finish it.
#: Long enough to install an authenticator app, far short of a full session.
MFA_ENROLLMENT_LIFETIME = timedelta(minutes=15)
#: Wrong codes one challenge allows before it is spent; sign in again after.
MFA_CHALLENGE_MAX_FAILURES = 5

API_TOKEN_PREFIX = "kvr_"


def authenticate_operator(session: Session, org_id: uuid.UUID, email: str, password: str) -> Operator | None:
    operator = session.scalars(select(Operator).where(Operator.org_id == org_id, Operator.email == email)).one_or_none()
    if operator is None:
        # Email addresses are case-insensitive in practice, and the login
        # rate limit already casefolds; an exact match still wins above so
        # two rows differing only in case keep working.
        operator = session.scalars(
            select(Operator).where(Operator.org_id == org_id, func.lower(Operator.email) == email.strip().lower())
        ).first()

    if operator is None or not operator.is_active or operator.password_hash is None:
        burn_password_check(password)
        return None

    now = datetime.now(UTC)
    if operator.locked_until is not None and operator.locked_until > now:
        burn_password_check(password)
        return None

    if not verify_password(password, operator.password_hash):
        record_failed_attempt(session, operator, now)
        return None

    # With a second factor enrolled the password is only half a sign-in, and
    # wrong codes count toward the same lockout: clearing the counter here
    # would let someone holding the password guess four codes, sign in again,
    # and repeat. `clear_failed_attempts` runs once the code is accepted.
    if not is_enrolled(operator):
        clear_failed_attempts(operator)
    operator.last_login_at = now
    if needs_rehash(operator.password_hash):
        operator.password_hash = hash_password(password)

    return operator


def clear_failed_attempts(operator: Operator) -> None:
    """Reset the lockout counter after a complete, successful sign-in."""
    operator.failed_login_attempts = 0
    operator.locked_until = None


def record_failed_attempt(session: Session, operator: Operator, now: datetime) -> None:
    """Count a failed password in the database, not in Python.

    ``failed_login_attempts += 1`` on the loaded object is a read-modify-write:
    N parallel guesses all read the same count and all write count + 1, so
    the lockout never triggers. A single ``UPDATE ... SET n = n + 1 RETURNING
    n`` is atomic under concurrency, and the lock is set from the value the
    database returned.
    """
    attempts = session.execute(
        update(Operator)
        .where(Operator.id == operator.id)
        .values(failed_login_attempts=Operator.failed_login_attempts + 1)
        .returning(Operator.failed_login_attempts),
        execution_options={"synchronize_session": False},
    ).scalar_one()
    if attempts >= LOCKOUT_THRESHOLD:
        session.execute(
            update(Operator).where(Operator.id == operator.id).values(locked_until=now + LOCKOUT_DURATION),
            execution_options={"synchronize_session": False},
        )
    # Keep the loaded object in step with the row for the rest of the request.
    session.expire(operator, ["failed_login_attempts", "locked_until"])


def create_session(
    session: Session,
    operator: Operator,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
    mfa_state: str = MFA_STATE_VERIFIED,
) -> tuple[OperatorSession, str]:
    raw_token = generate_token()
    now = datetime.now(UTC)
    # Challenge and enrolment sessions only finish sign-in, so they live
    # minutes, not days.
    lifetime = {
        MFA_STATE_CHALLENGE: MFA_CHALLENGE_LIFETIME,
        MFA_STATE_ENROLL: MFA_ENROLLMENT_LIFETIME,
    }.get(mfa_state, SESSION_ABSOLUTE_LIFETIME)
    session_row = OperatorSession(
        id=uuid.uuid4(),
        operator_id=operator.id,
        token_hash=hash_token(raw_token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + min(SESSION_SLIDING_WINDOW, lifetime),
        absolute_expires_at=now + lifetime,
        ip_address=ip_address,
        user_agent=user_agent,
        mfa_state=mfa_state,
    )
    session.add(session_row)
    session.flush()
    return session_row, raw_token


def touch_session(session_row: OperatorSession) -> None:
    now = datetime.now(UTC)
    session_row.last_seen_at = now
    session_row.expires_at = min(now + SESSION_SLIDING_WINDOW, session_row.absolute_expires_at)


def revoke_session(session_row: OperatorSession) -> None:
    session_row.revoked_at = datetime.now(UTC)


def revoke_operator_sessions(
    session: Session,
    operator_id: uuid.UUID,
    *,
    keep_token_hash: str | None = None,
) -> int:
    """Revoke every live session of an operator, optionally sparing one.

    Used after a password change (sparing the session that made it) and an
    admin reset (sparing none), so a stolen session does not outlive the
    password it was opened with. Returns the number of sessions revoked.
    """
    stmt = (
        update(OperatorSession)
        .where(OperatorSession.operator_id == operator_id, OperatorSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
        .execution_options(synchronize_session="fetch")
    )
    if keep_token_hash is not None:
        stmt = stmt.where(OperatorSession.token_hash != keep_token_hash)
    result = session.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)


def revoke_operator_api_tokens(session: Session, operator_id: uuid.UUID) -> int:
    """Revoke every live API token of an operator. Returns the count."""
    result = session.execute(
        update(ApiToken)
        .where(ApiToken.operator_id == operator_id, ApiToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
        .execution_options(synchronize_session="fetch")
    )
    return int(getattr(result, "rowcount", 0) or 0)


def create_api_token(
    session: Session, operator: Operator, name: str, *, expires_at: datetime | None = None
) -> tuple[ApiToken, str]:
    raw_token = generate_token(prefix=API_TOKEN_PREFIX)
    token_row = ApiToken(
        id=uuid.uuid4(),
        org_id=operator.org_id,
        operator_id=operator.id,
        name=name,
        token_hash=hash_token(raw_token),
        token_prefix=raw_token[: len(API_TOKEN_PREFIX) + 8],
        expires_at=expires_at,
    )
    session.add(token_row)
    session.flush()
    return token_row, raw_token


def revoke_api_token(token_row: ApiToken) -> None:
    token_row.revoked_at = datetime.now(UTC)


@dataclass(frozen=True)
class BearerAuth:
    """Who a bearer token authenticates, and how: through a session (with its
    MFA state) or an API token (``session_row`` None)."""

    operator: Operator
    session_row: OperatorSession | None

    @property
    def mfa_state(self) -> str:
        return self.session_row.mfa_state if self.session_row is not None else MFA_STATE_VERIFIED

    @property
    def is_api_token(self) -> bool:
        return self.session_row is None


def lookup_bearer(session: Session, raw_token: str) -> BearerAuth | None:
    """Resolve a bearer token to its operator, whatever its MFA state.

    Callers must check ``mfa_state``; ``lookup_operator_by_bearer_token``
    does that for everything except the sign-in and enrolment routes.
    """
    token_hash = hash_token(raw_token)
    now = datetime.now(UTC)

    session_row = session.scalars(select(OperatorSession).where(OperatorSession.token_hash == token_hash)).one_or_none()
    if session_row is not None:
        if session_row.revoked_at is not None or session_row.expires_at <= now:
            return None
        session_operator = session.get(Operator, session_row.operator_id)
        if session_operator is None or not session_operator.is_active:
            return None
        touch_session(session_row)
        return BearerAuth(session_operator, session_row)

    api_token_row = session.scalars(select(ApiToken).where(ApiToken.token_hash == token_hash)).one_or_none()
    if api_token_row is not None:
        if api_token_row.revoked_at is not None:
            return None
        if api_token_row.expires_at is not None and api_token_row.expires_at <= now:
            return None
        operator = session.get(Operator, api_token_row.operator_id)
        if operator is None or not operator.is_active:
            return None
        api_token_row.last_used_at = now
        return BearerAuth(operator, None)

    return None


def lookup_operator_by_bearer_token(session: Session, raw_token: str) -> Operator | None:
    """The operator a fully verified session or an API token belongs to."""
    auth = lookup_bearer(session, raw_token)
    if auth is None or auth.mfa_state != MFA_STATE_VERIFIED:
        return None
    return auth.operator
