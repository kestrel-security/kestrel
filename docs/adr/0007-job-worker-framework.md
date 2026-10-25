# ADR-0007: Job/Worker Framework

## Status

Accepted

## Context

Connector syncs and policy evaluations need a durable, retryable, observable background-job framework. The product spec mandates Redis and says "Celery or an equivalent durable job framework." We considered Celery, `arq` (simpler, asyncio-native), and Prefect (heavier, workflow-orchestration-focused).

## Decision

**Celery**, with Redis as both broker and result backend (`apps/worker`).

## Why

- `arq` is elegant and asyncio-native, but our collectors are I/O-bound without being async-first by design (the GitHub connector's `Transport` protocol is a simple synchronous `httpx.Client`/fixture-replay interface, not `async def`), so arq's core advantage doesn't clearly pay off yet.
- Celery has mature `celery beat` scheduling, well-understood retry/backoff primitives, and broad familiarity among contributors likely to already know it — relevant given the spec's emphasis on connector-run observability (rate limits, errors, retries, schedules). Its task-per-connector-run model maps directly onto the `ConnectorRun` row lifecycle (`pending` → `running` → `success`/`partial_failure`/`failed`).
- Prefect is workflow-orchestration-focused (DAGs of dependent tasks, richer scheduling UI) — meaningfully heavier than what "run this connector sync, then evaluate policies" needs at this stage.

## Consequences

- `apps/worker/src/kestrel_worker/tasks/sync.py`'s `run_connector_sync` task runs policy evaluation as an in-task post-processing step (same DB session, same transaction boundary as the sync itself) rather than enqueuing a second Celery message — matching the connector lifecycle's "evaluate affected policies" as the sync's own last step, not a separately-scheduled job. `tasks/evaluate.py`'s `evaluate_policies` task still exists standalone for out-of-band re-evaluation (e.g. after installing a new pack).
- `apps/worker/src/kestrel_worker/beat_schedule.py` was intentionally empty in v1 — `ConnectorInstance.schedule_cron` was modeled in the schema for forward compatibility, but translating per-instance cron schedules into Celery beat's static schedule map was deferred until the API needed to expose scheduled (rather than manually/API-triggered) syncs. **Update: this deferral is now closed.** Because beat's schedule map is static and can't vary per DB row, the resolution was *not* one beat entry per instance but a single every-60s dispatcher entry (`kestrel.schedule.dispatch_scheduled_syncs`) that reads `schedule_cron` itself and enqueues the instances that are due. This keeps beat's config static while the actual schedule stays per-tenant data. See `docs/operations/scheduled-syncs.md` for the delivery semantics (at-least-once, no backfill of missed fires) and the single-beat-process deployment constraint. The choice remains lower-stakes and easily revisited: swapping the task queue implementation is contained entirely behind `apps/worker` and the `kestrel_api.tasks_client` producer shim, and doesn't touch the sync/findings pipeline logic in `kestrel/sync` or `kestrel/findings` at all.
