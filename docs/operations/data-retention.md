# Data retention

Kestrel stores two categories of data that grow without bound and need an explicit retention decision: `raw_source` provenance payloads, and append-only history (`events`, `audit_log`, `connector_runs`).

**Status:** `raw_source` trimming and `policy_evaluations` pruning are implemented and tested. Retention for the history tables is a documented manual procedure — see [History tables](#history-tables).

## Why `raw_source` needs a policy

Every collected entity keeps the verbatim provider response in `raw_source`. That is deliberate: it's what lets a finding say "here is exactly what the API returned", which is the difference between evidence and an assertion.

It is also, for the same reason, the most sensitive data Kestrel holds — provider payloads routinely include email addresses, group names, resource titles, and other detail far beyond the normalized columns — and it grows for as long as an entity exists.

## Trimming `raw_source`

```bash
# Preview first -- changes nothing.
kestrel retention trim-raw-source --older-than-days 365 --dry-run

# Then apply.
kestrel retention trim-raw-source --older-than-days 365
```

Programmatically: `kestrel.retention.raw_source.trim_raw_source(session, org_id=..., older_than_days=..., dry_run=...)`. It does not commit — the caller owns the transaction.

### What it actually does

- **Entities are never deleted.** Only the `raw_source` column is rewritten. Deleting an `Identity` or `Resource` to reclaim space would tear holes in the access graph, silently resolve findings that are still true, and orphan historical `events`. Trimming is a redaction, not a purge.
- **Trimmed payloads become a tombstone**, `{"_kestrel_raw_source_trimmed": true, "trimmed_at": "..."}`, not `NULL`. `raw_source` is `NOT NULL`, and making it nullable would push "missing, or deliberately trimmed?" onto every reader. Use `kestrel.retention.raw_source.is_trimmed` to check.
- **Selection is on `last_seen_at`, not `created_at`.** An identity created three years ago but present in every sync is live data; trimming it would discard provenance for a currently-true finding. The window means "not observed recently".
- **Idempotent.** Already-tombstoned rows are skipped, so re-running reports 0 rather than re-counting.
- **Org-scoped**, like every other query.
- **Reversible by re-syncing.** The next sync overwrites the tombstone with a fresh payload, since upserts key on `(application_instance_id, provider_object_id)`.

Covers every model carrying `ProvenanceMixin`: `Identity`, `Group`, `Role`, `Permission`, `Resource`, `OAuthApplication`.

### Choosing a window

There is no default, and nothing runs automatically — the command requires an explicit `--older-than-days`. Retention length is a compliance and policy decision, not something Kestrel should assume on an operator's behalf.

A reasonable starting point is to keep provenance at least as long as your incident-investigation window (commonly 90–365 days). Trimming too aggressively degrades the evidence behind older findings; a finding stays valid and keeps its `FindingEvidence` rows, but the underlying payload it was derived from is gone.

### Scheduling it

Deliberately not wired into Celery beat. Unlike connector syncs — where the schedule is per-instance data — retention is a single global policy whose blast radius is data loss, so it stays an explicit operator action. To automate it, run the CLI from a cron job or Kubernetes `CronJob` against the worker image:

```yaml
# Sketch -- Kestrel ships no Kubernetes manifests.
kind: CronJob
spec:
  schedule: "0 4 * * 0"   # weekly, Sunday 04:00
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: retention
              image: <kestrel worker image>
              command: ["kestrel", "retention", "trim-raw-source", "--older-than-days", "365"]
```

Run it with `--dry-run` first in any environment where you have not run it before.

## Pruning `policy_evaluations`

Every evaluation pass writes one `policy_evaluations` row per enabled policy. Only the recent end of that history is read (the policy page's evaluation list, at most 100 rows; a connector run's detail page).

```bash
kestrel retention prune-policy-evaluations --dry-run
kestrel retention prune-policy-evaluations --keep-per-policy 100
```

It keeps the newest `--keep-per-policy` rows (default 100) for each policy across all its versions, and never deletes a row a finding references (`findings.policy_evaluation_id`, the evaluation that first opened it). Older connector runs' detail pages lose their evaluation list once it is pruned. Programmatically: `kestrel.retention.policy_evaluations.prune_policy_evaluations(session, org_id=..., keep_per_policy=..., dry_run=...)`; it does not commit. Schedule it the same way as `trim-raw-source` (a weekly `CronJob` is plenty).

## History tables

These grow with activity rather than with entity count, and have **no automated cleanup** today:

| Table | Grows with | Notes |
|---|---|---|
| `events` | Attribute changes per sync | The change history behind "what changed, when". |
| `audit_log` | Operator actions | Append-only by design; see `docs/api.md` → Audit log. |
| `connector_runs` | Sync frequency | One row per run, plus `object_counts`. |

Trim these with ordinary SQL against a retention cutoff, after taking a backup. Be aware that `audit_log` is frequently the table a compliance regime requires you to keep *longest* — check your obligations before deleting from it.

## Related

- `SECURITY.md` → Data retention
- `docs/operations/scheduled-syncs.md` — why sync scheduling *is* automated and this is not
