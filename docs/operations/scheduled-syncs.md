# Scheduled connector syncs

Each `ConnectorInstance` can carry a `schedule_cron` expression. When set, Kestrel enqueues a sync for that instance on that schedule, in addition to any manual syncs triggered via the API, UI, or CLI.

**Status:** implemented. Previously `schedule_cron` was modeled in the schema but never read.

## How it works

Celery beat's schedule map is static — it can't vary per database row. So instead of registering one beat entry per connector instance, the chart/compose runs a **single dispatcher** entry:

```
beat (every 60s) → kestrel.schedule.dispatch_scheduled_syncs
 → reads every ConnectorInstance with schedule_cron set
 → for each one that is due, enqueues kestrel.sync.run_connector_sync
```

The dispatcher lives in `apps/worker/src/kestrel_worker/tasks/schedule.py`; the beat entry itself is in `apps/worker/src/kestrel_worker/beat_schedule.py`.

Syncs dispatched this way are recorded with `ConnectorRun.triggered_by = "schedule"`, so scheduled and manual runs are distinguishable in run history.

## The events-only poll

`schedule_cron` governs the **full inventory** sync — the directory walk that
produces the Changes diff. Provider audit logs are different: they are
append-only and cursored, so they can be re-read every few minutes at a
fraction of that cost. A second beat entry does exactly that:

```
beat (every 300s) → kestrel.schedule.dispatch_event_syncs
 → every instance with a schedule_cron set, whose connector
 manifest declares an object type with supports_incremental
 → enqueues run_connector_sync(object_types=[those types])
```

An instance is eligible only if it already has a `schedule_cron`. Polling an
instance an operator only ever syncs by hand would be a surprise, so the
inventory schedule is also the on/off switch for the events poll.

**These runs are marked `is_incremental`.** They are a `success` — they read
everything they set out to — but they are not a full inventory, so:

- deletion detection and graph snapshotting are suppressed for them
- they never count as the Changes baseline (the first successful *full* run)
- they never satisfy connector freshness, so a five-minute poll cannot keep a
 connector green while its full sync has been failing for days
- they do not re-evaluate the whole org unless they changed inventory: a poll
 that only stored new activity evaluates only `RESOURCE_TYPE=event` policies,
 and one that brought nothing new evaluates nothing (see
 [findings](../findings.md#when-evaluation-runs))

Run history on the instance page still lists them.

### Cursors

`connector_cursors` holds one high-water mark per (instance, object type).
Cursors advance only for object types a run actually collected, only when the
run did not fail, and only to the time collection **started** — anything that
happened during the run may not have been visible to it.

The watermark handed back to a collector is the stored one minus a 15-minute
**overlap window**. Provider audit logs are eventually consistent, so asking
for the exact last boundary drops events. Re-reading a few minutes twice is
free: audit rows upsert on `(application_instance_id, provider_object_id)`, so
a re-read updates the row it already wrote, and audit rows never reach the
Changes feed at all.

**The first run reads a bounded window.** A cursored object type with no
cursor yet is handed a watermark of `KESTREL_SYNC_INITIAL_LOOKBACK_HOURS`
(default `24`) before the run started, not the provider's whole default
window. GitHub's web audit log keeps 180 days and Okta's System Log seven; on
a large tenant reading all of it exhausts the hourly request budget or the
page cap, the run fails, the cursor never advances, and the next run repeats
it. Raise the variable to backfill more history on a fresh instance, or set it
to `0` to read the provider's full default window. Full-inventory object types
are unaffected: they are always walked in full.

Which object types are polled is the connector's declaration, not a setting:
`supports_incremental: true` on a manifest object type. Today that is Okta's
`system_log`; Slack's `audit_log` and GitHub's follow.

## The posture trend capture

A third beat entry has nothing to do with connectors. The dashboard's trend
widget reads one `posture_trend_snapshots` row per org per UTC day, and
`kestrel.posture.capture_daily_snapshot` is what writes them:

```
beat (every 3600s) → kestrel.posture.capture_daily_snapshot
 → for every org: upsert today's open-by-severity and factor counts
```

Hourly rather than daily on purpose. The capture is an idempotent upsert keyed
on `(org_id, snapshot_date)`, so re-running it within a day costs nothing and
keeps today's figure current; a daily entry would mean a worker restart at the
wrong hour silently loses that day's point. One org's failure is logged and
rolled back on its own, so it cannot cost every other org its data point.

There is **no backfill**. A snapshot records what posture was on the day it
ran; the series legitimately starts the day the worker first ran it, and the
UI reports when history began rather than inventing earlier days from today's
findings.

## Setting a schedule

**Web UI:** on `/connectors`, each instance card has a schedule editor (presets + custom cron). Clear removes the schedule. Creating via `/connectors/new` can set an initial schedule.

Via the API (requires `analyst` role or higher):

```bash
curl -X PATCH "$KESTREL_API/connector-instances/$INSTANCE_ID/schedule" \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"schedule_cron": "*/30 * * * *"}'
```

Clear it by sending `{"schedule_cron": null}`. A `schedule_cron` can also be supplied when creating an instance via `POST /connector-instances`.

Expressions are standard 5-field cron (minute, hour, day-of-month, month, day-of-week), validated with `croniter` at write time — an invalid expression is rejected with `400` rather than silently never firing. Schedule changes are recorded in the audit log as `connector_instance.schedule_updated`.

## Running beat

Beat is a **scheduler**, not a worker. Exactly one beat process must run per deployment — two means every scheduled sync is dispatched twice.

**Docker Compose:** beat is embedded in the worker (`celery... worker --beat`, the worker image's default command), which is right for a single node. Nothing extra to run.

**Your own orchestration:** to scale workers, run beat as its own single-replica service (the worker image with `celery -A kestrel_worker.celery_app beat`) and override the workers' command to drop `--beat`. Stop the old beat before starting a new one during an update, so two schedulers never overlap.

## One sync per instance

Two syncs of the same instance must never interleave, so three guards apply:

- The worker takes a Redis lock (`kestrel:sync:<instance id>`, `SET NX EX`)
  for the duration of the run and returns `skipped:already_running` when it is
  held. `KESTREL_SYNC_LOCK_TTL_SECONDS` (default 1800) bounds how long a dead
  worker can hold it, but the effective TTL is never shorter than the task's
  hard time limit plus 60 seconds (1860 with the defaults below), so a lock
  cannot expire under a run that is still inside its time limit.
  `KESTREL_SYNC_LOCK_BACKEND=memory` selects a process-local lock for eager
  Celery and tests.
- `POST /connector-instances/{id}/sync` answers **409** while a `RUNNING` run
  younger than the TTL exists, and both beat dispatchers skip such instances.
- A `RUNNING` run older than the TTL is a worker that died; the API, the health
  center, and the next sync attempt mark it `FAILED` ("did not finish") so the
  connector never reads as syncing forever.

The task also carries `soft_time_limit` / `time_limit`
(`KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS`, default 1500, and
`KESTREL_SYNC_TIME_LIMIT_SECONDS`, default 1800), `acks_late`, and automatic
retries with backoff for transport errors only. Authentication, permission,
and data errors are not retried: they would fail the same way three times.

## Known limitations

- **The events poll has no per-instance cadence.** It is a fixed 300s beat
 entry for every eligible instance. An operator picks their inventory cadence
 via `schedule_cron`; this one is not theirs to tune.
- **Missed fires are caught up for 24 hours, as one sync.** The dispatcher keeps a per-instance ledger in Redis (`kestrel:schedule:last:<instance id>`, expiring after 24 hours) and dispatches the latest fire since the last one it sent. A fire that falls between two late dispatcher ticks (beat drift, or the dispatch task queued behind long syncs) still runs. If beat is down for a while, the instance gets one catch-up sync, not one per missed fire. Fires older than 24 hours are not replayed, and a schedule whose period is longer than that relies on the one-minute window below. There is no `connector_instances` column for this, so a Redis flush forgets the ledger.
- **Each fire is dispatched once while Redis is up.** Dispatching claims the fire with `SET NX` on `kestrel:schedule:fired:<instance id>:<fire time>`. A second dispatcher tick in the same minute, or two dispatchers racing, enqueue it once. A fire that lands while the instance is already syncing is consumed, not queued behind the running sync.
- **Without Redis, the old one-minute window applies.** If the ledger is unreachable, the dispatcher considers only fires in the minute before it ran. It can then skip a fire when ticks drift more than a minute apart, or dispatch twice when two ticks land in one minute. The instance lock makes a duplicate a no-op, and syncs are idempotent in any case: entities upsert by `(application_instance_id, provider_object_id)`.
- **No per-instance jitter.** Many instances sharing one expression (e.g. `0 * * * *`) all enqueue at once. Celery's queue absorbs this, but stagger expressions if you have many live connectors hitting rate-limited APIs.
## Related

- ADR-0007 (job/worker framework) — beat schedules were explicitly deferred in v1; this closes that deferral.
- `docs/deployment.md` — general deployment topology.
