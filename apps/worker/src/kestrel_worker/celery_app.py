# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import os

from celery import Celery
from kestrel.env import getenv_bool
from kestrel.observability.metrics import start_metrics_server
from kestrel.observability.startup import observability_enabled
from kestrel.observability.tracing import configure_tracing

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6380/0")

# Both of these are process-global side effects -- configure_tracing installs an
# OpenTelemetry provider and start_metrics_server binds a TCP port -- which made
# this module unimportable from a test process without them. Guarded so worker
# and beat processes behave exactly as before while tests import it quietly.
# See kestrel.observability.startup for the env contract.
if observability_enabled():
    configure_tracing("kestrel-worker")
    start_metrics_server()

app = Celery("kestrel_worker", broker=REDIS_URL, backend=REDIS_URL)
# KESTREL_CELERY_TASK_ALWAYS_EAGER runs tasks inline in the calling process
# instead of shipping them to a broker, so a test can exercise a task end to end
# without a worker. Off by default: production must never run tasks eagerly.
_task_always_eager = getenv_bool("KESTREL_CELERY_TASK_ALWAYS_EAGER", False)
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_always_eager=_task_always_eager,
    # Surface failures as exceptions rather than a failed AsyncResult when eager.
    task_eager_propagates=_task_always_eager,
)
# Explicit imports, not app.autodiscover_tasks(): autodiscover_tasks expects
# each entry to be a package whose *.tasks submodule holds the tasks (e.g.
# "myapp" -> imports "myapp.tasks") -- our tasks live one level deeper, in
# submodules of the tasks package itself (kestrel_worker.tasks.sync,
# kestrel_worker.tasks.evaluate), which autodiscover_tasks does not recurse
# into. Importing them directly registers their @app.task-decorated
# functions the same way, without relying on a discovery convention that
# doesn't fit this package layout.
from kestrel_worker import beat_schedule  # noqa: E402  (applies app.conf.beat_schedule)
from kestrel_worker.tasks import dashboard_schedules as _dashboard_schedule_tasks  # noqa: E402,F401
from kestrel_worker.tasks import evaluate as _evaluate_tasks  # noqa: E402,F401
from kestrel_worker.tasks import finding_lifecycle as _finding_lifecycle_tasks  # noqa: E402,F401
from kestrel_worker.tasks import notifications as _notification_tasks  # noqa: E402,F401
from kestrel_worker.tasks import posture_trend as _posture_trend_tasks  # noqa: E402,F401
from kestrel_worker.tasks import schedule as _schedule_tasks  # noqa: E402,F401
from kestrel_worker.tasks import sync as _sync_tasks  # noqa: E402,F401
from kestrel_worker.tasks import webhooks as _webhook_tasks  # noqa: E402,F401

_ = beat_schedule  # imported for its side effect only
