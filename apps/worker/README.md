# kestrel-worker

The [Kestrel](../../README.md) background worker: a Celery app
(`kestrel_worker.celery_app`) that runs connector syncs, policy evaluation,
webhook delivery, dashboard schedules, and posture trend capture. The beat
schedule lives in `src/kestrel_worker/beat_schedule.py`; tasks in
`src/kestrel_worker/tasks/`. Celery uses Redis as its broker
([ADR-0007](../../docs/adr/0007-job-worker-framework.md)).

Run it locally as described in [`CONTRIBUTING.md`](../../CONTRIBUTING.md), or as
the `worker` service in either Compose stack.

Part of the Kestrel monorepo; not published to PyPI.
