# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Optional OpenTelemetry tracing. No-op until OTEL_EXPORTER_OTLP_ENDPOINT is set."""

from __future__ import annotations

import logging
import os
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from kestrel.env import getenv_bool
from kestrel.version import get_version

logger = logging.getLogger(__name__)

_CONFIGURED = False


def get_tracer(name: str = "kestrel") -> trace.Tracer:
    """Return a tracer (NoOp until ``configure_tracing`` installs a provider)."""
    return trace.get_tracer(name)


def configure_tracing(service_name: str) -> bool:
    """Install an OTLP (or console) TracerProvider when tracing is enabled via env.

    Activation:
    - ``OTEL_EXPORTER_OTLP_ENDPOINT`` — export via OTLP/HTTP (preferred)
    - ``KESTREL_OTEL_CONSOLE=1`` — also/alternatively print spans to stderr (local debug)

    Returns True when a real provider was installed. Safe to call more than once.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return isinstance(trace.get_tracer_provider(), TracerProvider)

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    console = getenv_bool("KESTREL_OTEL_CONSOLE", False)
    if not endpoint and not console:
        return False

    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", service_name),
            "service.version": os.environ.get("OTEL_SERVICE_VERSION", get_version()),
        }
    )
    provider = TracerProvider(resource=resource)

    if endpoint:
        # Lazy import so environments without the exporter package still import this module
        # if they only want console — but we declare the dep; import is fine.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        # SDK accepts base URL; append /v1/traces if the operator gave a bare host root.
        exporter: Any = OTLPSpanExporter(endpoint=_normalize_otlp_traces_endpoint(endpoint))
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info("otel tracing enabled (otlp endpoint configured, service=%s)", service_name)

    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        logger.info("otel tracing console exporter enabled (service=%s)", service_name)

    trace.set_tracer_provider(provider)
    _CONFIGURED = True
    return True


def _normalize_otlp_traces_endpoint(endpoint: str) -> str:
    """OTLP/HTTP exporter expects a full traces URL; accept a collector base URL too."""
    cleaned = endpoint.rstrip("/")
    if cleaned.endswith("/v1/traces"):
        return cleaned
    return f"{cleaned}/v1/traces"
