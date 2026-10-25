# Dashboards

`/dashboard` is the operator's home: a default posture overview plus any
number of named, org-scoped boards built from a constrained metric DSL, with
chart widgets, a daily posture trend, PDF export, and scheduled email (DEC-023). Boards stay under
the Dashboard nav; there is no separate reports hub.

## Boards and widgets

| Route | Purpose |
|-------|---------|
| `GET /dashboard` | The posture overview payload: open findings by severity, status, and age bucket; ownership (mine, unassigned); top failing policies; connector health; the first-run checklist; the posture trend series |
| `GET`/`PUT /dashboard/layout`, `POST /dashboard/layout/reset` | The current operator's layout of the default board (stored on `operators.ui_preferences`) |
| `POST /dashboard/first-run/dismiss`, `POST /dashboard/first-run/restore` | Hide the getting-started checklist for the current operator, or show it again (also on `operators.ui_preferences`) |
| `GET`/`POST /dashboards`, `GET`/`PATCH`/`DELETE /dashboards/{id}` | Org boards: name, visibility, `is_default` |
| `POST /dashboards/{id}/duplicate`, `/set-default`, `POST /dashboards/pin-home` | Clone a board; choose the org default; pin a board as your home |
| `PUT /dashboards/{id}/layout` | Widget grid positions (`x`, `y`, `w`, `h`) |
| `POST /dashboards/{id}/widgets`, `PATCH`/`DELETE /dashboards/{id}/widgets/{widget_id}` | Add, edit, remove a widget: title, `query_spec`, visualization |
| `GET /dashboards/presets` | The built-in widget catalog as DSL presets |
| `POST /dashboards/query/preview` | Run a `query_spec` and return the series without saving |
| `POST /dashboards/{id}/export` | PDF or CSV of the board; recorded in `dashboard_exports` |
| `GET`/`POST /dashboards/{id}/schedules`, `PATCH`/`DELETE /dashboards/{id}/schedules/{schedule_id}` | Cron email schedules to org operators |

The board menu duplicates a board, pins it as your home, or deletes it after
a confirmation that names the board and its widget count. Home cannot be
deleted; non-admins can delete only boards they created; deleting a board
clears any operator's home pin that pointed at it. An explicit `?id=` in the
URL wins over a pinned home.

Edit mode adds a widget (preset or DSL), picks a visualization
(`DashboardVizType`: kpi, table, bar, pie, donut, line, area, list, markdown), sizes it, and
drags it on the grid. Every widget drills down to the filtered Findings or
Integrations view behind it. Read-only operators can view and export; admins
author org boards and schedules.

## Built-in widgets

The default board reproduces the posture overview; the catalog adds optional
widgets. All are presets over the DSL, so they can be copied and modified.

| Preset | In default board | Data |
|--------|------------------|------|
| `first_run` | when incomplete | Connect → pack → sync → triage checklist, injected at the top until every step is done or the operator dismisses it (the card's × or menu); "Show getting-started checklist" in the board menu brings it back |
| `summary_metrics` | yes | Open totals, criticals, stale connectors |
| `open_by_severity`, `by_status` | yes | Findings grouped by severity / status |
| `top_failing_policies` | yes | Policies by open finding count |
| `recent_open_findings` | yes | Newest open findings |
| `aging_open_findings` | optional | Open findings by age bucket |
| `connector_health` | optional | Instances by health |
| `my_open_findings`, `unassigned_open` | optional | Ownership queues |
| `posture_trend` | optional | Daily open-by-severity and labeled factor counts as sparklines |

## The metric DSL

Widgets never run SQL. A `query_spec` is allowlisted JSON evaluated by
`kestrel/src/kestrel/dashboard/query_dsl.py`, always scoped to the caller's
org:

```json
{
  "entity": "finding",
  "filters": [
    {"field": "status", "op": "eq", "value": "open"},
    {"field": "severity", "op": "in", "value": ["high", "critical"]}
  ],
  "group_by": ["severity"],
  "metric": {"fn": "count", "field": "*"},
  "order_by": [{"field": "count", "dir": "desc"}],
  "limit": 10,
  "time_range": {"field": "opened_at", "last": "30d"}
}
```

- `entity`: `finding`, `connector`, or `posture_trend`
- `filters`: a list of `{field, op, value}`. Findings allow `status`, `severity`,
  `subject_type`, `assigned_to_operator_id` (`"me"` for the viewer),
  `application_type`, `application_instance_id`, `first_seen_at`/`opened_at`,
  and `last_seen_at`; connectors allow `health` and `sync_mode` with
  `eq`, `neq`, `in`, or `not_in`. `posture_trend` takes no filters.
- `group_by`: `status`, `severity`, `subject_type` for findings; one of
  `health`, `sync_mode` for connectors. Omit it for a single count (KPI).
- `metric.fn`: `count` or `count_distinct`
- `order_by`, `limit` (capped at 100), and `time_range` (`last` as `Nd` or `Nh`,
  or `since`/`until`)

A finding widget counts every finding that matches its filters, like the
`open_by_severity` and `by_status` presets, unless its `time_range` says
otherwise; the Add widget dialog stores one only when you pick a "First seen"
window. The board, exports, and scheduled emails all run the stored spec, and
each card shows its window ("All time" or "First seen in the last 30 days").
The time range in the dashboard header drives posture-trend charts only.

Anything outside the allowlist is rejected at validation, which is what keeps
tenant scoping and injection out of the widget layer. Results are cached
briefly per org.

## Posture trend

`posture_trend_snapshots` holds one row per org per UTC day: open findings by
severity, labeled factor counts (open criticals, detection gaps, toxic
combinations, stale connectors), and how many factors
warrant attention. It is deliberately not a composite score and never
back-filled: missing days stay missing from the series. The worker's beat runs
`kestrel.posture.capture_daily_snapshot` hourly, an idempotent upsert of
today's row for every org, so a live deployment's trend starts on the day it
is installed. The demo seed writes a back-dated history directly.

## Export and email

PDF and CSV export render the board server-side and record an audit row.
In CSV, chart widgets write `widget,label,value` rows; a posture-trend widget
writes its own header row (`widget,date,open_total,attention_count,sev_*`)
followed by one row per day. The PDF shows the trend as a compact table of the
last ten days.
Schedules run on the worker's beat, render the same export, and send it
through the organization's mail server (Settings → Email, or the
`KESTREL_SMTP_*` default in `.env.example`); with none configured the transport
logs and sends nothing.
Recipients are org operators only; external recipients are not supported.
