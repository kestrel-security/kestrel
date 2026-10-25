# kestrel-api

The [Kestrel](../../README.md) HTTP API: a FastAPI application
(`kestrel_api.main:app`) over the core `kestrel` library. Routers live in
`src/kestrel_api/routers/`; middleware (request logging, origin check, rate
limiting) in `src/kestrel_api/middleware/`. Background work is enqueued to the
worker through `tasks_client.py`.

Run it locally with `uv run uvicorn kestrel_api.main:app --reload --port 8010`
(see [`CONTRIBUTING.md`](../../CONTRIBUTING.md)), or as the `api` service in
either Compose stack. The route reference is [`docs/api.md`](../../docs/api.md).

Part of the Kestrel monorepo; not published to PyPI.
