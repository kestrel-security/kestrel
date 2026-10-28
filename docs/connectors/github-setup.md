# GitHub connector setup

End-to-end guide for connecting a GitHub organization to Kestrel. The same steps
are embedded in **Integrations → Add integration** (and the instance detail page)
from `connectors/github/manifest.yaml`.

## Prerequisites

- A Kestrel deployment with the `kestrel-connector-github` package installed
- Org owner (or equivalent) access on the target GitHub organization
- Prefer **live** sync mode for real posture data; use **fixtures** only for demos/CI

## Choose an auth method

| Method | Best for | Secrets |
|--------|----------|---------|
| Personal Access Token (classic) | Quick start, small orgs | `token` |
| Personal Access Token (fine-grained) | Org-level collection with per-permission scopes; no enterprise endpoints | `token` |
| GitHub App | Production, rotation, installation scope | `app_id`, `installation_id`, `private_key` |

Fine-grained PATs (`github_pat_…`) are supported for organization-level
collection. Grant, under the organization as resource owner: Organization →
Members, Administration, Webhooks, Actions (read); Repository → Metadata,
Contents (read). They cannot reach GitHub Enterprise Cloud endpoints
(`/enterprises/{slug}/*`), so `enterprise_slug` has no effect with them; use a
classic PAT with `read:enterprise` or a GitHub App for enterprise-layer
collection.

Config for every method: `org_login` = organization slug (same as External tenant ref).

## Option A — Classic Personal Access Token

1. Sign in as an org owner → [Your organizations](https://github.com/settings/organizations).
2. Open [Personal access tokens (classic)](https://github.com/settings/tokens) → **Generate new token (classic)**.
3. Enable scopes:
 - `read:org` — members and teams
 - `read:user`
 - `repo` — private repo metadata / collaborators
 - `read:audit_log` — org audit events (event policies)
4. Generate, copy `ghp_…`, paste into Kestrel **Token** (Secrets step).
5. Set **org_login** / External tenant ref to the org slug.
6. Create the connector → **Test connection** → **Sync now**.

## Option B — GitHub App

1. [GitHub Apps](https://github.com/settings/apps) → **New GitHub App** (webhooks optional/off for Kestrel sync).
2. Permissions (read-only):
 - Repository: Metadata (and Contents if needed)
 - Organization: Members, Administration; audit log read when your plan allows Apps access
3. Create the App, note **App ID**, generate and download a **private key** (`.pem`).
4. Install on the target org only. Copy **installation ID** from the installation URL or [Installations](https://github.com/settings/installations).
5. In Kestrel, auth method = GitHub App; paste `app_id`, `installation_id`, PEM `private_key`; set `org_login`.
6. **Test connection** (mints an installation token) → **Sync now**.

## After connect

- Secrets are envelope-encrypted (`KESTREL_MASTER_KEY`); API responses never return plaintext.
- Enable a schedule on the instance if you want continuous syncs.
- Install / enable policies (`packs/github-posture`) and open Findings after the first successful sync.

## Coverage limits

Kestrel reports what it could actually read rather than assuming a full sync.

| Data | Requirement | Behaviour when unavailable |
|------|-------------|----------------------------|
| Audit log events | GitHub Enterprise Cloud, plus `read:audit_log` | The run completes as **partial coverage**; every other object type still syncs, and Test connection says the audit log is unavailable. Event policies produce no new findings. |
| Member 2FA state | Organization **owner** (a non-owner org admin gets 403) | `mfa_enabled` becomes unknown (`null`) rather than false. MFA policies deliberately do **not** fire on unknown, so a lost permission cannot open a finding on every administrator. |
| Member disabled state | Not exposed by GitHub Cloud | `is_disabled` is only set from `suspended_at`, which GitHub Enterprise Server sends. On GitHub Cloud the two `github-disabled-*` policies cannot fire. |

A run with reduced coverage also **skips deletion detection and snapshotting**,
because deletion is inferred from absence: treating an unreadable object type
as an empty one would report the whole family as deleted in Changes. Real
deletions are picked up by the next complete run.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Test connection fails 401 | Invalid or expired credential; for SSO-protected orgs, the token was never authorized for the organization |
| Test connection fails 403 naming a scope | That scope is missing. The message names it — classic PATs need `read:org`, `read:user`, `repo` |
| Run status "partial coverage" | An optional family (usually the audit log) could not be read. `error_summary` on the run names it and why |
| Empty audit events | Token/App lacks audit log access, or the org is not on GitHub Enterprise Cloud |
| A real action missing from events | The taxonomy is curated, not exhaustive — see below |
| Rate limited | GitHub signals primary limits with **403** plus `x-ratelimit-remaining: 0`. Kestrel waits out short resets and fails the run rather than blocking a worker for a long one |
| SSRF / invalid URL errors | Not applicable to the GitHub.com API host; check you did not override the base URL |

## Related

- Package README: `connectors/github/README.md`
- Authoring / SDK: `docs/connectors/authoring-tutorial.md`
- Manifest setup schema: `setup_steps` / `field_help` on each `auth_methods` entry

## Org security surface

Beyond membership and repository access, Kestrel collects the org-level
configuration that actually decides how an organization gets compromised:

| Family | Endpoint | What it answers |
|--------|----------|-----------------|
| Actions permissions | `/actions/permissions` + `/permissions/workflow` | Which actions may run, and whether every workflow starts with a write-scoped `GITHUB_TOKEN` |
| Runner groups | `/actions/runner-groups` | Whether self-hosted runners are reachable from public repositories |
| Self-hosted runners | `/actions/runners` | What is registered, and whether it is online |
| Actions secrets | `/actions/secrets` | Names and visibility (GitHub never returns values) |
| Actions variables | `/actions/variables` | Names and visibility — **values are dropped at collection** |
| Org webhooks | `/hooks` | Where org events are delivered, and whether TLS verification is off |
| Installed Apps | `/installations` | Which Apps hold org-wide access, and their permission sets |
| SSO credentials | `/credential-authorizations` | Which personal credentials are SAML-authorized, and when last used |
| Rulesets | `/rulesets` | Org-level protection, including rulesets set to `evaluate` that enforce nothing |
| Security managers | `/security-managers` | Teams holding the org-wide security role |
| Custom org roles | `/organization-roles` | Roles carrying management permissions |
| Pending invitations | `/invitations` | Unaccepted invites, including admin ones |
| PAT requests | `/personal-access-token-requests` | Fine-grained PAT requests awaiting a decision |
| Approved PATs | `/personal-access-tokens` | Fine-grained PATs granted access to org resources, with their permission sets |
| IP allow list | GraphQL `organization.ipAllowListEnabledSetting` / `ipAllowListEntries` | Whether the allow list is enforced, and its entries |
| Copilot | `/copilot/billing` + `/copilot/billing/seats` | Copilot policy settings and seat assignments |
| Packages | `/packages` | Organization packages and their visibility |

**Two things are never stored.** Webhook destination URLs routinely carry a
credential in the path or query string, so only the host and scheme are kept —
the full URL never reaches Kestrel's database. Actions *variable* values are
returned by GitHub's API and are dropped before collection, because operators
put things in variables that belong in secrets. Both redactions happen at
collection time, not in the normalizer, since `raw_source` is persisted
verbatim.

**Coverage depends on the credential.** Every family here is optional, and a
classic PAT reads few of them: GitHub gates org runners, hooks, and settings
behind `admin:org` / `admin:org_hook`, which are write-shaped scopes that
Kestrel's read-only enforcement rejects. A GitHub App expresses the same reads
as granular read-only permissions and gets most of the surface. Whichever you
use, families you cannot read are reported as **partial coverage** naming each
one — never as a failed sync, and never as data that disappeared.

**Member email.** `/orgs/{org}/members` never returns an email address. On an
org with SAML SSO, Kestrel reads the SAML NameID and SCIM username for each
linked member through GraphQL (`organization.samlIdentityProvider.externalIdentities`)
and uses that as the identity's email, which is what cross-app correlation
joins on. An org without SAML SSO, or a credential that cannot read the
identity provider, reports `member.saml_identity` as reduced coverage and
GitHub identities correlate by display name only. Outside collaborators are
never SSO-linked and never carry an email.

**Not yet collected:** SAML configuration detail (the identity-provider
settings themselves, as opposed to the identity list read for member email) is
GraphQL-only on GitHub's API and is not part of this surface. The org IP allow
list, also GraphQL-only, *is* collected (`org_ip_allow_list`).

**One honest limit:** `github-sso-credential-stale` needs
`credential_accessed_at`, which GitHub does not always populate. Where it is
absent the policy stays quiet rather than firing on every credential — missing
evidence is not evidence of disuse.

## Per-repository posture

Repository-level settings are collected as **subject-scoped settings** attached
to the repository they govern, so a policy reads
`resource["settings_by_key"]["repo_default_branch_protected"]` rather than
parsing a repo name out of a tenant setting key.

| Family | What it answers |
|--------|-----------------|
| Branch protection | Is the default branch protected; required reviews, admin enforcement, force pushes, deletions, linear history |
| Rulesets | Repo-level rules, including ones set to `evaluate` that enforce nothing |
| Webhooks | Destination host and TLS-verification state (URL redacted, as for org hooks) |
| Deploy keys | Present, and whether writable — a push credential outside the member and team model |
| Environments | Deployment environments and whether they require reviewers |
| Actions permissions | Whether Actions runs here, and which actions are allowed |
| GHAS / secret scanning / push protection / Dependabot | Enablement per repository |
| Vulnerability alerts / code scanning default setup | Whether Dependabot vulnerability alerts are enabled, and the code-scanning default-setup state |
| Secret-scanning / Dependabot / code-scanning alerts | **Count of open alerts only** — never the detected secret or the alert contents |

### Which repositories get scanned

Deep posture is roughly six API calls per repository. On a thousand-repo org
that is a classic PAT's entire hourly budget, so it runs against a risk tier
rather than everything:

- **public and internal** repositories — reachable beyond the team that owns
 them, so their protection settings matter most;
- repositories with an **outside collaborator** or a **direct admin** grant —
 access that bypasses the team model.

GHAS and secret-scanning *enablement* is read from the repository list payload,
costs nothing extra, and therefore covers **every** repository regardless of
tier.

Override with connector config:

| Key | Effect |
|-----|--------|
| `deep_scan_all: true` | Scan every repository |
| `deep_scan_repos: ["a", "b"]` | Scan exactly these (also accepts a comma-separated string) |
| `deep_scan_limit: 200` | Cap the selection; default 200 |

Exceeding the cap is reported as **reduced coverage**, not silently truncated.
That is deliberate: scanning a prefix and calling the run complete would make
the next full run report every unscanned repository's posture as deleted.

### Absence versus inaccessibility

GitHub 404s an unprotected branch, a repository with Actions unavailable, and
one without secret scanning. Those are **answers** — an unprotected default
branch is the finding — so they are recorded as such. A 403 is a genuine
permission or plan gate and is reported as reduced coverage. A rate limit is
neither and fails the run.

## What the audit log collects

Kestrel requests `include=web`, `order=asc`, and — once a cursor exists — a
`created:>=` phrase for everything since the last run's watermark minus a
15-minute overlap.

`include=web` is pinned rather than left to GitHub's default or set to `all`.
Git events (`git.clone`, `git.push`, `git.fetch`) are the overwhelming majority
of `all` and are operational telemetry, not posture; collecting them would bury
real configuration change in both the event-policy window and the Changes actor
overlay. Pinning it also means a change to GitHub's default cannot silently
alter what Kestrel ingests.

The action map is **curated, not exhaustive**. It covers org membership and
privilege, two-factor enforcement, teams, repository access, branch protection
and rulesets, webhooks, deploy keys, Actions secrets and self-hosted runners,
GitHub Apps and OAuth authorizations, fine-grained PAT grants, SAML/SSO, IP
allow lists, and GHAS/secret-scanning enablement. Two families are deliberately
excluded:

- **Git events**, for the volume reason above.
- **Code-scanning, Dependabot, and secret-scanning alerts.** That is ASPM
 (application security posture management), which is out of scope. GHAS
 *enablement* is posture and is collected as a setting instead.

An action outside the map still produces an event if its payload shows a
privileged permission being handed out — whatever GitHub decides to call the
action next.

Every entry with an actor, mapped or not, is also a sign of life for that
member: the latest one per actor becomes the identity's `last_active_at`
(source `audit`), and a Copilot seat's `last_activity_at` does the same
(source `analytics`). GitHub exposes no sign-in time per member, so "last
sign-in" on GitHub means "last org-visible action". Without audit-log access
members keep no activity timestamp and dormancy policies report them as not
assessable rather than dormant.

Repository visibility is the one action read from its payload rather than its
name: `repo.access` fires in both directions, and only the transition to public
is recorded.
