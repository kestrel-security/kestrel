# ADR-0009: Python Policies via RestrictedPython

## Status

Accepted (supersedes ADR-0002)

## Context

the legacy policy DSL (ADR-0002) was a custom policy language intended to be readable by non-programmers. Product direction shifted to a Panther-style model: security engineers write Python policy functions over normalized SaaS inventory, with AI assisting draft generation. Untrusted / AI-authored Python is a blast-radius concern.

## Decision

1. Policies are Python modules with module-level metadata (`POLICY_ID`, `SEVERITY`, `RESOURCE_TYPE`, …) and a required `policy(resource) -> bool` (True = compliant; False = finding).
2. Source is stored in `PolicyVersion.source_text` (same column formerly holding the legacy policy DSL).
3. Execution uses a `PolicyRuntime` protocol:
   - Default: `SubprocessPolicyRuntime` — RestrictedPython compile in-process; evaluate in a short-lived child (`python -m kestrel.policies.runtime.worker`) with a wall-clock timeout (`KESTREL_POLICY_EVAL_TIMEOUT_SECONDS`).
   - Opt-in: `RestrictedPythonRuntime` via `KESTREL_POLICY_RUNTIME=restricted` for fast local loops.
   - Container isolation may replace the subprocess implementation later without changing callers.
4. Row loading reuses the flat dict shape in `kestrel.policies.dataload` (identity, grant, tenant_setting, **event**).
5. AI generation (`generate_policy_draft`) returns drafts only; operators must validate, dry-run, and create. Prompts include resource schemas from `kestrel.policies.resource_schemas`. After generate, RestrictedPython validation is always returned (`validation`); optional one repair chat turn when the LLM draft fails compile; optional `include_fixtures` scaffold is never persisted and never auto-enables.
6. `RESOURCE_TYPE = "event"` evaluates over synced `ActivityEvent` rows; findings fan out through existing outbound webhooks (SIEM/Tines).

## Consequences

- the legacy policy DSL package, grammar, and `.kestrel` packs are removed.
- Pack policies are `.py` files; fixture tests call `policy()` directly on fixture rows.
- Threat model: policy code is semi-trusted org content; RestrictedPython + subprocess isolation mitigate, but are not a full sandbox / gVisor.
- Event detections reuse findings + webhooks — no separate alert bus in v1.
