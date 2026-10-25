# GitOps — `kestrel export` / `plan` / `apply`

Workflow for declaring org desired state in Git. **Enforcing**
repo-as-source-of-truth (UI read-only, block API writes) is not implemented
(deferred).

## Manifest (`kestrel.yaml`)

```yaml
apiVersion: kestrel.dev/v1
kind: DesiredState
packs:
  - id: github-posture
    path: packs/github-posture
policies:
  - path: policies/my_custom_policy.py
    enabled: true
connectors:
  - name: Acme GitHub
    type: github
    external_tenant_ref: acme-github
    sync_mode: fixtures
    config:
      org_login: acme
    secrets:
      - field: token
        ref: env:GITHUB_TOKEN
exceptions:
  - policy: my-custom-policy
    reason: Accepted risk for Q3
    expires_at: "2026-12-31T00:00:00Z"   # optional
```

An `exceptions` entry covers every match of that policy while it is
unexpired: evaluation records them as `exception` findings instead of opening
them, and once `expires_at` passes they reopen (see
[findings lifecycle](findings.md#reconciliation)).

## Commands

```bash
kestrel export -o ./gitops-out          # writes kestrel.yaml + policies/
kestrel plan ./gitops-out               # exit 1 on drift; --json for CI
kestrel apply ./gitops-out              # idempotent; --dry-run supported
# also: kestrel gitops export|plan|apply
```

## Secrets

Never put plaintext credentials in `config`. Use `secrets: [{ field, ref }]`,
where `ref` is either `env:<NAME>` (an environment variable to read the value
from) or `secret:<field>` (a secret already stored on the instance; this is
what `kestrel export` writes for every stored secret). Any other scheme, or a
`value:` key, is rejected. Apply creates/updates instances and schedules
without writing ciphertext — set secrets via API/CLI after apply.

## Example

See `examples/gitops/` for a sample manifest and GitHub Actions workflow.
