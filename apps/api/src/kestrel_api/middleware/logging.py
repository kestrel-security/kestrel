# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Structured JSON request logging, request-id header, and Prometheus HTTP metrics.

OpenTelemetry spans for the request path are created when tracing is configured
(see ``kestrel.observability.tracing``); otherwise ``get_tracer`` is a no-op.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid

from kestrel.observability.metrics import observe_http_request
from kestrel.observability.tracing import get_tracer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("kestrel_api.access")


def _handler_label(request: Request) -> str:
    """Prefer the matched route template over the raw path (avoids UUID cardinality)."""
    route = request.scope.get("route")
    path = getattr(route, "path", None) if route is not None else None
    return path or request.url.path


# A client-supplied correlation id is echoed into the response and the access
# log, so it is accepted only when it looks like one.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        supplied = request.headers.get("X-Request-Id", "")
        request_id = supplied if _REQUEST_ID_RE.match(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.monotonic()
        tracer = get_tracer("kestrel.api")
        handler = _handler_label(request)

        with tracer.start_as_current_span(
            "http.request",
            attributes={
                "http.method": request.method,
                "http.route": handler,
                "kestrel.request_id": request_id,
            },
        ) as span:
            response = await call_next(request)
            # Route may only be bound after the ASGI app runs; refresh label.
            handler = _handler_label(request)
            duration_s = time.monotonic() - started
            duration_ms = round(duration_s * 1000, 2)
            response.headers["X-Request-Id"] = request_id
            operator_id = getattr(request.state, "operator_id", None)
            span.set_attribute("http.status_code", response.status_code)
            if operator_id is not None:
                span.set_attribute("kestrel.operator_id", str(operator_id))

            observe_http_request(
                method=request.method,
                handler=handler,
                status_code=response.status_code,
                duration_seconds=duration_s,
            )
            logger.info(
                json.dumps(
                    {
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "handler": handler,
                        "status_code": response.status_code,
                        "duration_ms": duration_ms,
                        "operator_id": str(operator_id) if operator_id else None,
                    }
                )
            )
            return response
