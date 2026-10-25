# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Defense-in-depth CSRF protection: 403s state-changing requests whose
Origin header (if present) doesn't match an allow-listed origin.

This is deliberately a backstop, not the primary CSRF defense. FastAPI's
auth is a bearer token in the Authorization header, never a cookie -- a
cross-site request can't forge a custom header the way it auto-attaches
cookies, so classic CSRF doesn't apply to this API as currently architected
(only the Next.js app, which owns the actual session cookie, needs the
real defense: httponly/secure/samesite=lax + Next's built-in Server Action
origin checks). This middleware exists for the case FastAPI's port is ever
accidentally reachable from a browser.
"""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

STATE_CHANGING_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


class OriginCheckMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_origins: list[str] | None = None) -> None:
        super().__init__(app)
        env_origins = os.environ.get("ALLOWED_ORIGIN", "")
        self.allowed_origins = set(allowed_origins or []) | {o.strip() for o in env_origins.split(",") if o.strip()}

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin")
        if (
            request.method in STATE_CHANGING_METHODS
            and origin is not None
            and self.allowed_origins
            and origin not in self.allowed_origins
        ):
            return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
        return await call_next(request)
