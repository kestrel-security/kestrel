# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared FastAPI dependencies: DB session, bearer-token authentication,
role gating, and current-org resolution.

FastAPI has one uniform bearer-token mechanism (`Authorization: Bearer
<opaque token>`), checked against either OperatorSession (browser-driven,
via Next.js forwarding its httponly cookie as a header) or ApiToken
(CLI/automation) rows -- same header, same get_current_operator dependency.
See docs/adr/0008-opaque-tokens-for-operator-auth.md.

Kestrel is deployed one org per instance (see ADR-0006), so
get_current_org derives the org from the authenticated operator rather than
routing on it -- multi-org delegation, if built, layers on top later
rather than retrofitting org-scoping in.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, Header, HTTPException, Request
from kestrel.auth.rbac import role_satisfies
from kestrel.auth.service import BearerAuth, lookup_bearer
from kestrel.db.models.operator import (
    MFA_STATE_CHALLENGE,
    MFA_STATE_ENROLL,
    MFA_STATE_VERIFIED,
    Operator,
    OperatorRole,
)
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.notifications.email import use_email_dispatcher
from sqlalchemy.orm import Session

from kestrel_api.middleware.rate_limit import remember_validated_token
from kestrel_api.tasks_client import enqueue_notification_emails


def get_db() -> Generator[Session, None, None]:
    session = get_sessionmaker()()
    # Notification email leaves through the worker, not inside the request.
    use_email_dispatcher(session, enqueue_notification_emails)
    try:
        yield session
    finally:
        session.close()


#: The 403 detail for a session that has not finished MFA. Not 401: the
#: credential is valid, and clients treat 401 as "signed out".
_MFA_STATE_ERRORS = {
    MFA_STATE_CHALLENGE: {
        "code": "mfa_challenge_required",
        "message": "Enter your authentication code to finish signing in.",
    },
    MFA_STATE_ENROLL: {"code": "mfa_enrollment_required", "message": "Set up two-factor authentication to continue."},
}


def _authenticate(
    request: Request, request_authorization: str | None, db: Session, allowed_states: frozenset[str]
) -> BearerAuth:
    if not request_authorization or not request_authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    raw_token = request_authorization.removeprefix("Bearer ").strip()
    auth = lookup_bearer(db, raw_token)
    if auth is None:
        raise HTTPException(status_code=401, detail="Invalid, expired, or revoked token")
    if auth.mfa_state not in allowed_states:
        raise HTTPException(status_code=403, detail=_MFA_STATE_ERRORS.get(auth.mfa_state, "Not allowed"))
    # lookup_bearer slid the session's expiry (or stamped the token's
    # last_used_at). Read-only handlers never commit, so without this the
    # sliding window only moved on requests that happened to write.
    db.commit()
    # From now on this token has its own rate-limit bucket; until it
    # authenticated, its requests counted against the client IP.
    remember_validated_token(raw_token)

    # Stashed for RequestLoggingMiddleware, which runs after the route (and
    # therefore after this dependency) resolves, and for routes that care how
    # the caller authenticated (minting API tokens).
    request.state.operator_id = auth.operator.id
    request.state.raw_token = raw_token
    request.state.bearer = auth
    return auth


def get_current_operator(
    request: Request,
    request_authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> Operator:
    """The caller, through an API token or a fully signed-in session."""
    return _authenticate(request, request_authorization, db, frozenset({MFA_STATE_VERIFIED})).operator


def get_bearer_for_mfa_challenge(
    request: Request,
    request_authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> BearerAuth:
    """Only a session waiting for its second factor (POST /auth/login/mfa)."""
    return _authenticate(request, request_authorization, db, frozenset({MFA_STATE_CHALLENGE}))


def get_bearer_any(
    request: Request,
    request_authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> BearerAuth:
    """Any live credential, whatever its MFA state (sign-out only)."""
    states = frozenset({MFA_STATE_VERIFIED, MFA_STATE_CHALLENGE, MFA_STATE_ENROLL})
    return _authenticate(request, request_authorization, db, states)


def get_bearer_for_mfa_setup(
    request: Request,
    request_authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> BearerAuth:
    """A signed-in session or one limited to enrolment (MFA setup routes, /auth/me, logout)."""
    return _authenticate(request, request_authorization, db, frozenset({MFA_STATE_VERIFIED, MFA_STATE_ENROLL}))


def get_current_org(operator: Operator = Depends(get_current_operator), db: Session = Depends(get_db)) -> Organization:
    org = db.get(Organization, operator.org_id)
    if org is None:
        raise HTTPException(
            status_code=503,
            detail="No organization configured yet -- run `kestrel init` first.",
        )
    return org


def require_role(minimum: OperatorRole):
    def _dependency(operator: Operator = Depends(get_current_operator)) -> Operator:
        if not role_satisfies(operator.role, minimum):
            raise HTTPException(status_code=403, detail=f"Requires {minimum.value} role or higher")
        return operator

    return _dependency
