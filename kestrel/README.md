# kestrel (core library)

The core of [Kestrel](../README.md): the normalized identity/access data model,
the connector SDK, the access graph, the Python policy runtime, findings,
change detection, and the `kestrel` CLI (`kestrel init`, `kestrel demo`,
`kestrel policy`, `kestrel connector`, `kestrel secrets`, …).

It has no dependency on the API or the worker; both import it. Code lives under
`src/kestrel/`, one package per area (`connectors/`, `graph/`, `policies/`,
`findings/`, `changes/`, `secrets/`, `db/`, `cli/`, …).

This package is part of the Kestrel monorepo and is not published to PyPI (the
`kestrel` name there belongs to an unrelated project). Install it from a
checkout with `uv sync`. See [`docs/architecture.md`](../docs/architecture.md)
and [`CONTRIBUTING.md`](../CONTRIBUTING.md).
