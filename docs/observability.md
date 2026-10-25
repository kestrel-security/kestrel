# Observability

## Current (implemented
- FastAPI `RequestLoggingMiddleware`: structured JSON access logs (`request_id`, method, path, handler, status, duration, `operator_id`) plus `X-Request-Id`
- Prometheus metrics (always on):
  - API: `GET /metrics` (public, same trust model as `/healthz`)
  - Worker: optional scrape HTTP server when `KESTREL_METRICS_PORT` is set (Compose sets `9101`)
- OpenTelemetry tracing (optional): enabled when `OTEL_EXPORTER_OTLP_ENDPOINT` and/or `KESTREL_OTEL_CONSOLE=1` is set
- Celery worker logs at configured level
- Connector run rows: status, timing, error surfaces via API
- `/healthz` liveness for API (the process is up)
- `/readyz` readiness for API (its dependencies answer): 200 with
  `{"status": "ready", "checks": {...}}`, or 503 naming the failing dependency.
  Compose gates the `web` service on it, so the UI never starts against an API
  that cannot reach Postgres.

## Prometheus metrics

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `kestrel_http_requests_total` | counter | `method`, `handler`, `status_code` | API middleware |
| `kestrel_http_request_duration_seconds` | histogram | `method`, `handler` | API middleware |
| `kestrel_sync_runs_total` | counter | `status`, `trigger` | `kestrel.sync.pipeline.run_sync` |
| `kestrel_sync_duration_seconds` | histogram | `status` | sync pipeline |
| `kestrel_policy_evaluations_total` | counter | `status` | findings pipeline |
| `kestrel_policy_evaluation_duration_seconds` | histogram | `status` | findings pipeline |
| `kestrel_policy_matches_total` | counter | — | findings pipeline |
| `kestrel_webhook_deliveries_total` | counter | `status` | webhook delivery |
| `kestrel_webhook_delivery_duration_seconds` | histogram | `status` | webhook delivery |

`handler` is the FastAPI **route template** (e.g. `/api/v1/findings/{id}`), not the raw path, so UUID cardinality does not explode the series. Labels never include secrets, Authorization headers, or webhook target URLs.

### Local scrape (Docker Compose)

```bash
# API metrics (always available when the API is up)
curl -s http://localhost:8010/metrics | head

# Worker metrics (Compose publishes host port 9101)
curl -s http://localhost:9101/metrics | head

# Optional Prometheus that scrapes both:
docker compose --profile observability up -d
open http://localhost:9090
```

Scrape config: `deployments/observability/prometheus.yml`.

**Production note:** `/metrics` and the worker metrics port are unauthenticated by design (like `/healthz`). Restrict them with network policy / reverse-proxy ACLs; do not expose them on the public internet.

## OpenTelemetry tracing

Spans are created for:

- `http.request` (API)
- `kestrel.sync.run`
- `kestrel.policy.evaluate`
- `kestrel.webhook.deliver`

Activation (no vendor lock-in — OTLP/HTTP only):

| Env var | Effect |
|---------|--------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Export spans to an OTLP/HTTP collector (base URL or `…/v1/traces`) |
| `OTEL_SERVICE_NAME` | Override service name (`kestrel-api` / `kestrel-worker` defaults) |
| `OTEL_SERVICE_VERSION` | Override the `service.version` resource attribute; defaults to `kestrel.version.get_version()` (the `KESTREL_VERSION` stamp, else the installed `kestrel` package version, else `dev`) |
| `KESTREL_OTEL_CONSOLE=1` | Also print spans to stderr (local debug) |

Until one of those is set, `get_tracer()` is a no-op TracerProvider — zero export overhead beyond creating no-op spans.

### Startup guard (`KESTREL_ENABLE_OBSERVABILITY`)

Installing a TracerProvider and binding the worker's metrics port are
process-global side effects, so both are gated on `observability_enabled()`
(`kestrel/observability/startup.py`), consulted by `create_app()` in
`apps/api/src/kestrel_api/main.py` and by `kestrel_worker.celery_app` at import.

| Value | Effect |
|-------|--------|
| unset (default) | Enabled |
| `KESTREL_ENABLE_OBSERVABILITY=1` | Enabled |
| `KESTREL_ENABLE_OBSERVABILITY=0` | Disabled |

The guard deliberately does **not** detect pytest: shipping code that branches
on the presence of a test runner behaves differently under test than in
production. The test harness sets `KESTREL_ENABLE_OBSERVABILITY=0` itself in
the root `conftest.py`. Production, Compose, and local `uvicorn` / `celery`
runs need no configuration.

Example with a local collector (not bundled; bring your own):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
docker compose up api worker
```

## Structured logs — expectations

- JSON-friendly key=value or JSON logs over time
- Fields: `timestamp`, `level`, `service`, `request_id` / correlation, `org_id` (when available), `connector_run_id`
- **Never** log secrets, tokens, `Authorization` headers, or raw credential bodies

## Audit events

- Sync `events` for entity attribute changes
- Admin audit log for API mutations — `GET /audit-log`

## Connector / sync / queue health

- `ConnectorInstance` + `ConnectorRun` API
- Celery inspect (ops) — not productized yet
- Beat dispatches `schedule_cron` syncs — see `docs/operations/scheduled-syncs.md`

## Tenant-aware diagnostics

- Prefer `org_id` in logs/audit when available; **do not** put high-cardinality tenant ids on Prometheus labels in single-org deployments
- Avoid leaking other tenants’ identifiers in errors

## Sensitive-data redaction

- Use `kestrel.secrets.store.redact` for nested structures
- Logs, including automated tooling output, must not dump `.env`

## Alerting principles

- Alert on sync failure streaks, queue backup, elevated 5xx, webhook delivery failure rates, decryption failures
- Prefer actionable alerts over noisy scoreboards

## Operational dashboards

- Local: Prometheus UI via `--profile observability` (no Grafana board ships yet)
- Until a shared dashboard pack exists: Prometheus queries + container logs + Adminer (`profiles: [debug]`) for local only
