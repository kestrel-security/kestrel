# GitHub connector

Collects GitHub organization membership, teams, repository access, security
settings, and audit-log events for posture analysis. Read-only.

## Why

GitHub is where source, CI secrets, and deploy credentials live. The posture
questions are who administers the organization, who can reach which
repositories (directly, through a team, or as an outside collaborator),
whether two-factor authentication is enforced, and what changed in the audit
log.

## Object types

The rows below are the `object_types` in `manifest.yaml` (39), with the entity
kind each one maps to. Every family past the core inventory is optional: a
credential that cannot read it reduces the run's coverage rather than failing
the sync.

| Object type | Maps to | Notes |
|-------------|---------|-------|
| `organization` | setting | 2FA enforcement, member repository-creation and visibility settings |
| `member` | identity | Org members with role (`admin` / `member`) and 2FA state when the token can read it; email from the SAML identity list where the org has SSO |
| `team` | group | |
| `team_membership` | group_membership | |
| `team_repo_permission` | grant | Team → repository permission level |
| `repository` | resource | Visibility, archived, default branch |
| `repo_collaborator` | grant | Direct collaborator permission (including admin) |
| `outside_collaborator` | identity | Flagged `is_external`; the collaborator's repository access is emitted alongside as a grant |
| `audit_log` | event (incremental) | Curated organization audit-log taxonomy (membership and privilege, 2FA, teams, repository access and visibility, branch protection and rulesets, webhooks, deploy keys, Actions secrets and runners, Apps and OAuth, fine-grained PATs, SSO, IP allow lists, GHAS) as `ActivityEvent` rows; `include=web`, ascending, cursored from the previous run's watermark |
| `actions_permission` | setting | Allowed actions, enabled repositories, default `GITHUB_TOKEN` permissions, whether workflows can approve pull requests |
| `runner_group`, `self_hosted_runner` | setting | Runner groups (including public-repository reachability) and registered runners |
| `actions_secret`, `actions_variable` | setting | Names and visibility only; variable values are dropped at collection |
| `org_webhook` | setting | Destination host and scheme (URL redacted at collection), TLS verification state |
| `installed_app` | oauth_application | Installed GitHub Apps, with one `oauth_scope` per permission and sensitivity read from the permission level |
| `credential_authorization` | setting | SAML-authorized personal credentials and last use |
| `org_ruleset` | setting | Org rulesets, including ones that evaluate without enforcing |
| `security_manager` | setting | Teams holding the org-wide security-manager role |
| `custom_org_role` | role | Custom organization roles and the management permissions they carry |
| `org_invitation`, `pat_request` | setting | Pending invitations (admin ones flagged) and fine-grained PAT requests awaiting a decision |
| `org_ip_allow_list` | setting | Whether the org IP allow list is enforced, and its entries (GraphQL-only) |
| `copilot_policy`, `copilot_seat` | setting | Copilot policy settings and seat assignments (needs the Copilot business App permission) |
| `approved_pat` | setting | Fine-grained PATs granted access to org resources, with their permission sets; token values are never returned by GitHub |
| `org_package` | setting | Organization packages and their visibility |
| `repo_security_analysis` | setting (subject: repository) | GHAS, secret scanning, push protection, and Dependabot enablement; read from the repository list, so it covers every repository |
| `repo_branch_protection`, `repo_ruleset` | setting (subject: repository) | Default-branch protection (required reviews, admin enforcement, force pushes, deletions) and repo rulesets |
| `repo_webhook`, `deploy_key`, `repo_environment` | setting (subject: repository) | Webhook TLS state (URL redacted), deploy keys and whether writable, environments and reviewer requirements |
| `repo_actions_permission` | setting (subject: repository) | Whether Actions runs here, and which actions are allowed |
| `secret_scanning_alert`, `dependabot_alert`, `code_scanning_alert` | setting (subject: repository) | Count of open alerts only, never contents |
| `repo_vulnerability_alerts`, `repo_code_scanning` | setting (subject: repository) | Dependabot vulnerability-alert enablement and code-scanning default-setup state |

Per-repository families run against the deep-scan tier (public and internal
repositories plus those with an outside collaborator or direct admin grant,
capped by `deep_scan_limit`); see the setup guide.

## Fixture mode

`sync_mode=fixtures` replays the bundled `fixtures/` through the same collector
and normalizer with no network access. `fixtures/changed/` is the t0 → t1 pair
that backs the declared change classes.

```bash
uv run kestrel connector validate connectors/github
uv run pytest tests/unit/connectors -k github -q
```

## Live mode

Three auth methods, all walked through in **Integrations → Add integration →
GitHub** from this package's `manifest.yaml`, and in
[`docs/connectors/github-setup.md`](../../docs/connectors/github-setup.md):

- **Personal Access Token (classic):** `read:org`, `read:user`, `repo`, and `read:audit_log`. `repo` is a broad scope; it is required for private-repository metadata and collaborator access, and the setup guide says so.
- **Personal Access Token (fine-grained):** `github_pat_…` with read-only organization permissions (Members, Administration, Webhooks, Actions) and repository permissions (Metadata, Contents). Cannot reach GitHub Enterprise Cloud endpoints, so `enterprise_slug` has no effect with it.
- **GitHub App:** an App installed on the organization with read-only permissions; paste `app_id`, `installation_id`, and the PEM `private_key`. Preferred for production: installation-scoped credentials and easier rotation.

Set `org_login` to the organization login. **Test connection** probes the
token before the first sync and classifies failures (auth, permission,
rate limit, network). The audit log requires GitHub Enterprise Cloud; on other
plans that family is skipped and reported in the run, never treated as a
failure or as deletions. Rate-limit headers drive backoff; a page cap raises
rather than truncating.

Secrets are stored with envelope encryption
([ADR-0004](../../docs/adr/0004-secrets-storage-and-encryption.md)) and never
returned by the API.

## Honest limits

- Inventory is re-read in full on every run. The audit log is the one incremental family (`supports_incremental: true`): each run asks for events since the previous run's watermark minus a 15-minute overlap.
- Repository posture collects branch protection, rulesets, webhooks, deploy keys, environments, vulnerability alerts, code scanning default setup, and secret/Dependabot/code-scanning alert counts for the deep-scan tier. The control-by-control status is in [`docs/posture-baselines/github.md`](../../docs/posture-baselines/github.md).
- Repository posture costs several extra requests per repository. A gated answer degrades that repository to "unknown" and is recorded on the run; it never aborts the sync.
- The audit-log normalizer covers ~148 curated GitHub action types. Unmapped actions are still stored as `unknown` events; no events are dropped.
- Fine-grained PATs work for most org-level collection; they cannot reach GitHub Enterprise Cloud endpoints (`/enterprises/{slug}/*`). Use a classic PAT or GitHub App when enterprise-layer collection is needed.
- GitHub Enterprise Server is not a supported target.
- OAuth app access restrictions are not collectable via the REST API. The setting is tracked as not-collectable in the posture baseline matrix.
- No write-back.
