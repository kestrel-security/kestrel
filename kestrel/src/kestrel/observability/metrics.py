# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Prometheus metrics for API requests, sync, policy eval, and webhooks.

Uses the default ``prometheus_client`` registry. Metric names are stable and
documented in ``docs/observability.md``. Label values are low-cardinality
(method, route template, status class / enum) — never org ids or raw URLs.
"""

from __future__ import annotations

import logging
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from prometheus_client import REGISTRY as _REGISTRY
from prometheus_client import start_http_server as _start_http_server

from kestrel.env import getenv_str

logger = logging.getLogger(__name__)

# uvicorn --reload (and pytest re-imports) can re-execute this module; reclaim
# existing collectors instead of raising Duplicate timeseries.


def _counter(name: str, documentation: str, labelnames: list[str]) -> Counter:
    existing = _REGISTRY._names_to_collectors.get(name)
    if isinstance(existing, Counter):
        return existing
    return Counter(name, documentation, labelnames)


def _histogram(name: str, documentation: str, labelnames: list[str], buckets: tuple[float, ...]) -> Histogram:
    existing = _REGISTRY._names_to_collectors.get(name)
    if isinstance(existing, Histogram):
        return existing
    return Histogram(name, documentation, labelnames, buckets=buckets)


HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
JOB_DURATION_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)

HTTP_REQUESTS = _counter(
    "kestrel_http_requests_total",
    "HTTP requests handled by the Kestrel API",
    ["method", "handler", "status_code"],
)
HTTP_DURATION = _histogram(
    "kestrel_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "handler"],
    HTTP_DURATION_BUCKETS,
)

SYNC_RUNS = _counter(
    "kestrel_sync_runs_total",
    "Connector sync runs completed",
    ["status", "trigger"],
)
SYNC_DURATION = _histogram(
    "kestrel_sync_duration_seconds",
    "Connector sync wall time in seconds",
    ["status"],
    JOB_DURATION_BUCKETS,
)

POLICY_EVALUATIONS = _counter(
    "kestrel_policy_evaluations_total",
    "Policy evaluations completed",
    ["status"],
)
POLICY_DURATION = _histogram(
    "kestrel_policy_evaluation_duration_seconds",
    "Single policy evaluation wall time in seconds",
    ["status"],
    JOB_DURATION_BUCKETS,
)
POLICY_MATCHES = _counter(
    "kestrel_policy_matches_total",
    "Subjects matched by policy evaluation",
    [],
)

WEBHOOK_DELIVERIES = _counter(
    "kestrel_webhook_deliveries_total",
    "Outbound webhook delivery attempts",
    ["status"],
)
WEBHOOK_DURATION = _histogram(
    "kestrel_webhook_delivery_duration_seconds",
    "Outbound webhook delivery wall time in seconds",
    ["status"],
    JOB_DURATION_BUCKETS,
)


def observe_http_request(*, method: str, handler: str, status_code: int, duration_seconds: float) -> None:
    """Record one API request. ``handler`` should be a route template, not a raw path."""
    HTTP_REQUESTS.labels(method=method, handler=handler, status_code=str(status_code)).inc()
    HTTP_DURATION.labels(method=method, handler=handler).observe(duration_seconds)


def observe_sync_run(*, status: str, trigger: str, duration_seconds: float) -> None:
    SYNC_RUNS.labels(status=status, trigger=trigger).inc()
    SYNC_DURATION.labels(status=status).observe(duration_seconds)


def observe_policy_evaluation(*, status: str, duration_seconds: float, match_count: int = 0) -> None:
    POLICY_EVALUATIONS.labels(status=status).inc()
    POLICY_DURATION.labels(status=status).observe(duration_seconds)
    if match_count > 0:
        POLICY_MATCHES.inc(match_count)


def observe_webhook_delivery(*, status: str, duration_seconds: float) -> None:
    WEBHOOK_DELIVERIES.labels(status=status).inc()
    WEBHOOK_DURATION.labels(status=status).observe(duration_seconds)


def render_metrics() -> tuple[bytes, str]:
    """Return Prometheus exposition body and Content-Type."""
    return generate_latest(_REGISTRY), CONTENT_TYPE_LATEST


def start_metrics_server(port: int | None = None) -> int | None:
    """Start a scrape HTTP server (worker process). Returns the bound port or None if disabled.

    Port comes from ``port`` or ``KESTREL_METRICS_PORT``. Unset / empty / ``0`` skips.
    """
    raw = str(port) if port is not None else getenv_str("KESTREL_METRICS_PORT").strip()
    if not raw or raw == "0":
        return None
    try:
        bind_port = int(raw)
    except ValueError:
        logger.warning("invalid KESTREL_METRICS_PORT=%r; metrics HTTP server not started", raw)
        return None
    _start_http_server(bind_port)
    logger.info("prometheus metrics listening on 0.0.0.0:%s", bind_port)
    return bind_port


# Re-export for typing convenience in callers that want the registry object.
REGISTRY: Any = _REGISTRY
