# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Prometheus metrics and optional OpenTelemetry tracing.

Metrics are always registered; scrape them from the API ``/metrics`` endpoint
or the worker's optional metrics HTTP port. Tracing is a no-op unless
``OTEL_EXPORTER_OTLP_ENDPOINT`` is set — see ``docs/observability.md``.
"""

from kestrel.observability.metrics import (
    observe_http_request,
    observe_policy_evaluation,
    observe_sync_run,
    observe_webhook_delivery,
    render_metrics,
    start_metrics_server,
)
from kestrel.observability.tracing import configure_tracing, get_tracer

__all__ = [
    "configure_tracing",
    "get_tracer",
    "observe_http_request",
    "observe_policy_evaluation",
    "observe_sync_run",
    "observe_webhook_delivery",
    "render_metrics",
    "start_metrics_server",
]
