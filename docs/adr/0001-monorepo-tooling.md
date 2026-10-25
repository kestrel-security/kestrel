# ADR-0001: Monorepo Tooling

## Status

Accepted

## Context

Kestrel is a polyglot monorepo: a Python backend (API, worker, core library, connectors) and a TypeScript frontend (Next.js). We need a workspace/dependency-management strategy for each language, and a decision on whether a cross-language build orchestrator (Nx, Turborepo, Bazel) is warranted.

## Decision

- **Python**: [`uv`](https://docs.astral.sh/uv/) workspaces. The root `pyproject.toml` declares `[tool.uv.workspace]` with `kestrel`, `apps/api`, `apps/worker`, and each connector package (e.g. `connectors/github`) as members. `uv sync` from the repo root produces one shared virtual environment (`.venv`) with every member installed in editable mode, and one `uv.lock` covering the whole workspace.
- **TypeScript**: `pnpm` workspaces. The root `package.json` + `pnpm-workspace.yaml` list `apps/web` (the empty `packages/ui` shared-UI package was removed in 0.4.0; a shared package is added when a second consumer exists).
- **No cross-language build orchestrator** (Nx, Turborepo, Bazel) at this stage. Two ecosystems with straightforward dependency graphs don't yet justify the operational complexity of a build-graph tool.

## Why

- `uv` gives cargo-like workspace ergonomics: a single lockfile, fast installs, and editable cross-package imports (e.g. `connectors/github` depending on `kestrel` as `{ workspace = true }`) without manual `pip install -e` bookkeeping.
- Connector packages register themselves via `[project.entry-points."kestrel.connectors"]`, so `kestrel`'s core code never imports a specific connector directly — installing (or scaffolding) a new connector and running `uv sync` is the entire integration step. This is what makes "connector development without modifying core" concretely true rather than aspirational.
- `pnpm` is faster than `npm` and handles workspace-local package linking correctly; it's a low-stakes, easily-revisited choice.

## Consequences

- Contributors run `uv sync && pnpm install` once at the repo root (see `Makefile`'s `sync` target), not per-package installs.
- Adding a new connector or app means adding it to `[tool.uv.workspace].members` and re-running `uv sync` — documented in `docs/connectors/authoring-tutorial.md` and every connector scaffold's generated README.
- Revisit if CI time or cross-package build caching becomes a real bottleneck; a build-graph tool is additive at that point, not a rewrite.
