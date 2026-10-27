# Writing policies with an AI agent

Kestrel's built-in generator (`POST /policies/generate`) is one way to draft a
policy. This page is for the other way: an outside coding agent, such as Claude
Code, Cursor, or an MCP client, writing a policy file or calling the API for
you. The agent gets the same rules the built-in generator uses.

## 1. Read the contract first

The authoring contract lists everything a policy may use. It is generated from
the sandbox, so it is always current:

```bash
uv run kestrel policy contract               # Markdown
uv run kestrel policy contract --format json
```

or over the API (any operator role):

```http
GET /api/v1/policies/authoring-contract
GET /api/v1/policies/authoring-contract?format=markdown
```

It contains:

- **Helpers**: `now`, `within_last_days`, `days_since`, `parse_timestamp`,
  `duration_seconds`, `get_path`, `has_admin_grant`, `application_matches`,
  `email_domain`, `domain_matches`, `ip_in_networks`, `matches_any`,
  `PolicyDataError`, with signatures and docstrings.
- **Builtins and `time`**: the only other names that exist.
- **Rules**: what to return, how to handle missing and malformed data, and
  which shortcuts hide findings.
- **Idioms**: short snippets, each taken from a shipped pack policy you can
  open under `packs/`.
- **Row shapes**: the `resource` dict for each `RESOURCE_TYPE`.

Give the agent the Markdown contract as context, and point it at two or three
pack policies for the same connector (`packs/<connector>-posture/policies/`).

## 2. What agents get wrong

These are the mistakes the contract's rules exist to prevent:

| Mistake | Instead |
|---|---|
| `import datetime`, `datetime.now() - timedelta(days=30)` | `within_last_days(value, 30)` or `days_since(value)`; `now()` if you need the time |
| Comparing a row timestamp to a datetime | Timestamps arrive as ISO strings, naive, or aware datetimes. Use the helpers |
| Not scoping to one application | Start with `if application.get("type") != "okta": return True` |
| `if not identity.get("mfa_enabled")` | `None` means the connector could not read it. Only `is False` is a violation |
| `try: ... except Exception: return True` | Raise `PolicyDataError`; a guessed `True` hides findings |
| Logic at module level | The module body may only hold constants and functions |

## 3. Check every draft

Run the same checks the built-in generator runs, in order, and fix what each
one reports before moving to the next:

1. **Validate**: `kestrel policy validate <file>` or
   `POST /api/v1/policies/validate`. Reports compile errors and unknown names,
   with a "did you mean" for typos.
2. **Fixture test**: `kestrel policy test <file> --fixtures <json>` or
   `POST /api/v1/policies/test-draft`. Write fixtures for this intent,
   including near misses (a disabled account, another application, a missing
   timestamp), not just one matching row.
3. **Dry run**: `POST /api/v1/policies/dry-run-draft` evaluates the draft
   against live inventory without writing findings.

A person reviews and enables the policy. Agents never enable policies.
