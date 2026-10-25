# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application factory and the module-level ``app`` that uvicorn serves.

``create_app()`` builds a fresh, fully-wired application. The module-level
``app = create_app()`` at the bottom is what ``uvicorn kestrel_api.main:app``
(Docker, Compose, a host uvicorn) loads, so the deployment entrypoint is
unchanged -- the factory just makes it possible to build a second, isolated
instance (with its own ``dependency_overrides``) instead of mutating the
process-global one.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from kestrel.observability.metrics import render_metrics
from kestrel.observability.startup import observability_enabled
from kestrel.observability.tracing import configure_tracing
from kestrel.version import get_version

from kestrel_api.middleware.logging import RequestLoggingMiddleware
from kestrel_api.middleware.origin_check import OriginCheckMiddleware
from kestrel_api.middleware.rate_limit import RateLimitMiddleware
from kestrel_api.routers import (
    ai_settings,
    api_tokens,
    audit,
    auth,
    changes,
    connectors,
    dashboard,
    dashboards,
    email_settings,
    findings,
    graph,
    identities,
    mfa,
    notification_preferences,
    notifications,
    operators,
    org_security,
    packs,
    policies,
    resources,
    search,
    ticket_integrations,
    webhooks,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

ROUTERS = (
    auth,
    mfa,
    operators,
    org_security,
    api_tokens,
    dashboard,
    dashboards,
    changes,
    graph,
    identities,
    search,
    findings,
    resources,
    connectors,
    policies,
    packs,
    audit,
    webhooks,
    ticket_integrations,
    ai_settings,
    email_settings,
    notification_preferences,
    notifications,
)


def log_startup_warnings() -> None:
    """Deployment misconfigurations worth one loud line at boot.

    Never raises: a database that is still starting is `/readyz`'s problem,
    not a reason to crash the process.
    """
    if not os.environ.get("ALLOWED_ORIGIN", "").strip():
        logger.warning(
            "ALLOWED_ORIGIN is not set: the API accepts state-changing requests from any browser origin. "
            "Set it to the URL operators use (the Compose deployment derives it from APP_URL)."
        )
    try:
        from kestrel.db.session import get_sessionmaker
        from kestrel.secrets.crypto import EnvKeyProvider, MissingMasterKeyError
        from kestrel.secrets.rotation import rotation_status

        try:
            provider = EnvKeyProvider()
        except (MissingMasterKeyError, ValueError):
            return
        session = get_sessionmaker()()
        try:
            status = rotation_status(session, provider)
        finally:
            session.close()
    except Exception:  # startup diagnostics must never take the API down
        logger.debug("startup secrets check skipped", exc_info=True)
        return
    if status.unreadable_rows:
        logger.error(
            "%d stored secret(s) were encrypted with a master key this process does not hold; "
            "set KESTREL_MASTER_KEY_PREVIOUS and run `kestrel secrets rotate`",
            status.unreadable_rows,
        )
    elif status.stale_rows:
        logger.warning(
            "%d stored secret(s) are not under the current master key (%d legacy, pre-0.4.0); run `kestrel secrets rotate`",
            status.stale_rows,
            status.legacy_rows,
        )


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # An uninitialized checkout may have no key yet; a configured malformed
    # or short key must fail before the API declares itself healthy.
    from kestrel.secrets.crypto import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, EnvKeyProvider

    if os.environ.get(MASTER_KEY_ENV) or os.environ.get(PREVIOUS_MASTER_KEY_ENV):
        EnvKeyProvider()
    log_startup_warnings()
    yield


def create_app() -> FastAPI:
    """Build a fully-wired Kestrel API application."""
    # Installs a process-global OpenTelemetry provider, so it is env-guarded
    # (see kestrel.observability.startup) rather than run unconditionally.
    if observability_enabled():
        configure_tracing("kestrel-api")

    app = FastAPI(
        title="Kestrel API",
        version=get_version(),
        lifespan=_lifespan,
        license_info={
            "name": "Apache 2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
        },
    )
    # Middleware runs outermost-added-last-executed-first for requests.
    # Rate limiting sits outside logging so 429s are still access-logged;
    # OriginCheck stays as a CSRF backstop for state-changing requests.
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(RateLimitMiddleware)

    for router_module in ROUTERS:
        app.include_router(router_module.router, prefix="/api/v1")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Liveness plus the running build version, which a deploy pipeline can poll
        to confirm the new release is actually serving before it declares success."""
        return {"status": "ok", "version": get_version()}

    @app.get("/readyz")
    def readyz() -> Response:
        """Readiness: can this process actually serve requests?

        `/healthz` answers "the process is up", which a load balancer can use
        to decide whether to restart it. This answers "the dependencies it
        needs are reachable", which is what decides whether to send it traffic.
        A degraded dependency returns 503 with the failing check named, so an
        operator does not have to read logs to find out which one.
        """
        checks: dict[str, str] = {}

        try:
            from kestrel.db.session import get_sessionmaker
            from sqlalchemy import text

            session = get_sessionmaker()()
            try:
                session.execute(text("SELECT 1"))
                checks["database"] = "ok"
            finally:
                session.close()
        except Exception as exc:  # deliberately broad: readiness probe: any failure means "not ready"
            logger.warning("readiness check failed: database", exc_info=True)
            checks["database"] = f"unavailable: {type(exc).__name__}"

        try:
            import redis

            from kestrel_api.tasks_client import get_broker_url

            client = redis.Redis.from_url(get_broker_url(), socket_connect_timeout=2)
            client.ping()
            checks["broker"] = "ok"
        except Exception as exc:  # deliberately broad: readiness probe: any failure means "not ready"
            logger.warning("readiness check failed: broker", exc_info=True)
            checks["broker"] = f"unavailable: {type(exc).__name__}"

        ready = all(value == "ok" for value in checks.values())
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "degraded", "version": get_version(), "checks": checks},
        )

    @app.get("/metrics")
    def metrics() -> Response:
        """Prometheus text exposition. Public like /healthz — restrict at the network edge in production."""
        body, content_type = render_metrics()
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
