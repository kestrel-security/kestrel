# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Process-startup guard for the side-effecting observability wiring.

``configure_tracing`` and ``start_metrics_server`` are process-global side
effects (they install an OpenTelemetry provider and bind a TCP port). Running
them at import time makes a module impossible to import without those side
effects, so the API app factory and the Celery app both ask here first.

Controlled solely by ``KESTREL_ENABLE_OBSERVABILITY``, which defaults to on --
production and local ``uvicorn``/``celery`` runs keep today's behavior with no
configuration. Callers that need a quiet process set it to ``0``; the test
harness does this in the root ``conftest.py``.

This deliberately does *not* detect pytest. Shipping code that branches on the
presence of a test runner behaves differently under test than in production,
which is exactly the divergence a test suite exists to rule out.
"""

from __future__ import annotations

from kestrel.env import getenv_bool


def observability_enabled() -> bool:
    """True when this process should install tracing / start a metrics server."""
    return getenv_bool("KESTREL_ENABLE_OBSERVABILITY", True)
