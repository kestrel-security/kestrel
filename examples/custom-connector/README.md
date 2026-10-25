# Example: Kestrel Connector for "Acme Widgets"

> This directory started from `kestrel connector create acme-widgets` and was
> then extended (see `docs/connectors/authoring-tutorial.md` for the full
> walkthrough). It's here so you can read a finished connector package without
> running the command yourself -- it isn't wired into the workspace or
> registered as a real connector (see "Wiring in for real use" below for
> what that last step looks like).
>
> It is not byte-for-byte scaffold output. Compared with a fresh scaffold:
> the test is an end-to-end `tests/test_collection_identity.py` that runs the
> collector and normalizer together through `run_collection` (the scaffold
> writes a normalizer-only test module instead), `tests/conftest.py`
> puts `src/` on `sys.path` so the repository's root `pytest` run can collect
> it, and `pyproject.toml` carries fuller package metadata. It also omits the
> scaffold's `fixtures/changed/users.json` overlay and `change_classes`
> declaration, so it demonstrates collection and normalization but not the
> change-coverage contract.

Replace the example API calls in `client.py`, `collector.py`, and
`normalizer.py` with real calls to your application.

## Local validation (zero credentials)

    kestrel connector validate .

This runs the collector + normalizer against `fixtures/` via a
FixtureTransport -- no network access, no secrets required.

## Testing

    uv run pytest tests/

## Wiring in for real use

1. Add this directory to the root `pyproject.toml`'s `[tool.uv.workspace]`
   members list.
2. Run `uv sync` from the repo root -- this registers the
   `kestrel.connectors` entry point declared in this connector's
   `pyproject.toml`, so `kestrel sync` and the API can discover it by name
   ("acme-widgets").
3. See `example_policy.py` for a starting point on policies over this
   connector's data (`kestrel policy validate example_policy.py`).
