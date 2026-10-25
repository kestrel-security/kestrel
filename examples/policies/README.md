# Example policy

A minimal custom policy and its fixture file, the shape every policy in
`packs/` follows.

- `my_first_policy.py` — `policy(resource) -> bool`, where `True` means
  compliant and `False` opens a finding. It flags Slack Owners and Admins
  without two-factor authentication, reading the normalized `identity` resource
  (`identity.mfa_enabled`) and its `roles`. The module-level constants
  (`POLICY_ID`, `TITLE`, `SEVERITY`, `RESOURCE_TYPE`, `REMEDIATION`,
  `COMPLIANCE`) are the metadata Kestrel reads when the policy is installed.
- `my-first-policy.fixtures.json` — resources with the expected outcome for
  each, so the policy is tested without a database or a tenant.

Validate the module (it is compiled with RestrictedPython, the same way the
runtime compiles it) and run it against the fixtures:

```bash
uv run kestrel policy validate examples/policies/my_first_policy.py
uv run kestrel policy test examples/policies/my_first_policy.py \
  --fixtures examples/policies/my-first-policy.fixtures.json
```

The policy contract, the runtime, and how to ship a policy in a pack are in
[`docs/policies.md`](../../docs/policies.md).
