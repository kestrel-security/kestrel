# GitOps example

Sample desired-state manifest and a minimal GitHub Actions workflow that runs
`kestrel plan` (exit 1 on drift).

## Layout

```
examples/gitops/
  kestrel.yaml                 # desired state
  policies/
    example_custom.py          # custom policy referenced by the manifest
  github-actions-plan.yml    # copy to .github/workflows/kestrel-plan.yml
```

## Commands

```bash
# From repo root, with Postgres + `kestrel init` already done:
kestrel plan examples/gitops
kestrel apply examples/gitops
kestrel export -o ./my-export  # dump live state (secrets → refs only)
```

Secrets are **never** embedded in YAML. Connector `secrets[].ref` values are
placeholders (`env:…` / `secret:…`); set real credentials via the API/UI.

**Enforcing** repo-as-source-of-truth (UI read-only) is not implemented — see
`docs/gitops.md`.
