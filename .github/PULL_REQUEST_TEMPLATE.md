## Summary

<!-- What changed and why. Link the issue if there is one. -->

## Test plan

- [ ] `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy kestrel/src apps/api/src apps/worker/src connectors`
- [ ] `uv run pytest` (or a targeted subset that covers this change)
- [ ] If `apps/web` changed: `pnpm --filter kestrel-web lint && pnpm --filter kestrel-web typecheck && pnpm --filter kestrel-web build`
- [ ] Docs and `CHANGELOG.md` Unreleased updated when the change is user-facing

## Contributor agreement

- [ ] Each commit includes a `Signed-off-by:` line (`git commit -s`) per the Developer Certificate of Origin in `CONTRIBUTING.md` (the DCO check enforces it)
- [ ] This contribution is licensed under Apache License 2.0
- [ ] No secrets, tenant data, or live credentials are included
- [ ] `make hygiene` passes (no private identifiers or scanner findings — see `CONTRIBUTING.md`)
