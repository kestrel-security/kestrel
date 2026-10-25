# GitHub posture baseline matrix

**Vendor baseline:** CIS GitHub Benchmark v1.2.0 (March 2026)  
**Supplement:** GitHub org/repository hardening docs, NIST SP 800-218 (SSDF)

Profile levels: **L1** = CIS Level 1 (essential), **L2** = CIS Level 2 (defense in depth), **mon** = activity monitor

## Section 1 — Organization security

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 1.1.1 | Require 2FA for all org members | L1 | `tenant_setting.two_factor_requirement_enabled` | collected | `github-org-2fa-not-required` | high |
| 1.1.2 | Require 2FA for org owners/admins | L1 | identity roles + mfa_enabled | collected | `github-org-admin-without-mfa` | high |
| 1.1.3 | Block users without 2FA from org resources | L1 | `tenant_setting.two_factor_requirement_enabled` — the org requirement is the mechanism that blocks them, so this is the same signal as 1.1.1 | collected | `github-org-2fa-not-required` | high |
| 1.2.1 | Default repository permission not admin | L1 | `tenant_setting.default_repository_permission` | collected | `github-default-repo-permission-admin` | high |
| 1.2.2 | Restrict members creating public repos | L1 | `tenant_setting.members_can_create_public_repositories` | collected | `github-members-can-create-public-repos` | medium |
| 1.3.1 | SAML SSO enforced for org | L2 | org SAML config (GraphQL-only) | not-collectable | — | high |
| 1.3.2 | IP allow list enabled | L2 | org IP allow list | collected | `github-ip-allow-list-disabled` | medium |
| 1.4.1 | OAuth app access restrictions enabled | L2 | org OAuth app policy | not-collectable | — | high |

## Section 2 — Repository protection

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 2.1.1 | Default branch protected | L1 | repo setting `repo_default_branch_protected` | collected | `github-repo-default-branch-unprotected` | high |
| 2.1.2 | Require PR reviews before merge | L1 | repo setting `repo_required_reviews` | collected | `github-repo-no-required-reviews` | high |
| 2.1.3 | Require status checks before merge | L2 | branch protection required contexts | collected | `github-repo-required-checks-missing` | medium |
| 2.2.1 | No force-push on default branch | L1 | repo setting `repo_force_push_allowed` | collected | `github-repo-force-push-allowed` | high |
| 2.3.1 | Public repo visibility reviewed | L1 | visibility is collected, but whether it was *reviewed* is a process fact no API reports | not-collectable | — | medium |

## Section 3 — Supply chain & code security

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 3.1.1 | Secret scanning enabled | L1 | repo setting `repo_secret_scanning_enabled` | collected | `github-repo-secret-scanning-disabled` | high |
| 3.1.2 | Secret scanning push protection | L2 | repo setting `repo_secret_scanning_push_protection_enabled` | collected | `github-repo-push-protection-disabled` | high |
| 3.2.1 | Dependabot alerts enabled | L1 | dependabot alert counts | collected | `github-repo-dependabot-critical-alerts` | high |
| 3.2.2 | Dependabot security updates enabled | L2 | repo setting `repo_dependabot_security_updates_enabled` | collected | `github-repo-dependabot-disabled` | medium |
| 3.3.1 | Code scanning enabled | L2 | code scanning default setup | collected | `github-repo-code-scanning-disabled` | medium |

## Section 4 — GitHub Actions

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 4.1.1 | Restrict Actions to verified creators | L1 | org Actions permissions | collected | `github-actions-all-third-party-allowed` | high |
| 4.1.2 | Default GITHUB_TOKEN read-only | L1 | org workflow permissions | collected | `github-actions-default-token-write` | high |
| 4.2.1 | Self-hosted runners inventory | L2 | runner groups + runners | collected | `github-runner-group-allows-public-repos` | medium |

## Section 5 — Privileged access

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 5.1.1 | External collaborator admin access | L1 | grant + identity.is_external | collected | `github-external-collaborator-admin` | high |
| 5.1.2 | Direct repo admin bypassing teams | L1 | grant.granted_via=direct | collected | `github-direct-repo-admin` | medium |
| 5.2.1 | Disabled user retains org admin | L1 | identity.is_disabled + roles | collected | `github-disabled-org-admin` | critical |
| 5.2.2 | Disabled user retains repo admin | L1 | identity + grants | collected | `github-disabled-repo-admin` | critical |
| 5.2.3 | External org admin | L1 | identity.is_external + roles | collected | `github-external-org-admin` | high |
| 5.3.1 | Repo admin without MFA | L1 | identity.mfa_enabled + grants | collected | `github-repo-admin-without-mfa` | high |

## Section 6 — Audit & monitoring

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| 6.1.1 | Audit log streaming configured | L2 | org audit streaming | collected | `github-audit-log-streaming-not-configured` | medium |
| 6.2.1 | Privileged grant activity | mon | event action privilege.grant | collected | `github-activity-privileged-grant` | high |
| 6.2.2 | MFA disabled activity | mon | event action mfa.disable | collected | `github-activity-mfa-disabled` | critical |
| 6.2.3 | Sensitive OAuth consent | mon | event action oauth.sensitive_consent | collected | `github-activity-sensitive-oauth` | high |
| 6.2.4 | External privilege grant | mon | event action privilege.external | collected | `github-activity-external-privilege` | critical |
| 6.2.5 | Service account escalation | mon | event action service_account.escalate | collected | `github-activity-sa-escalation` | critical |
| 6.2.6 | Dormant identity reactivation | mon | event action dormant.reactivate | collected | `github-activity-dormant-reactivation` | medium |

## Section 7 — Kestrel controls (no external baseline equivalent)

CIS GitHub v1.2.0 does not enumerate these. They are shipped checks over data
the connector collects, listed so the coverage denominator is the whole pack.

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Org Actions secret readable by every repo | L2 | `actions_secret_visibility` | collected | `github-actions-secret-visible-to-all-repos` | medium |
| — | Workflows can approve pull requests | L1 | `can_approve_pull_request_reviews` | collected | `github-actions-workflows-can-approve-prs` | high |
| — | Installed App holds sensitive org permissions | L1 | `installed_app` + permission set | collected | `github-app-overpermissioned` | high |
| — | Outside collaborator on a sensitive repository | L1 | grant + resource sensitivity | collected | `github-external-collaborator-on-sensitive-repo` | critical |
| — | Private repositories may be forked out of the organization | L1 | `members_can_fork_private_repositories` | collected | `github-private-repo-forking-allowed` | medium |
| — | Org ruleset configured but not enforcing | L2 | `org_ruleset:{id}` enforcement | collected | `github-org-ruleset-not-enforced` | medium |
| — | Repository ruleset configured but not enforcing | L2 | `repo_ruleset:{id}` enforcement | collected | `github-repo-ruleset-not-enforced` | medium |
| — | Org webhook without TLS verification | L1 | `org_webhook:{id}` config | collected | `github-org-webhook-tls-disabled` | high |
| — | Pending invitation granting admin | L2 | `pending_invitation:{id}` role | collected | `github-pending-admin-invitation` | medium |
| — | Pending fine-grained PAT request covering every repository | L2 | `pat_request:{id}` repository_selection | collected | `github-pat-request-all-repositories` | medium |
| — | Administrators bypass branch protection | L2 | `repo_branch_protection_detail` | collected | `github-repo-admins-bypass-protection` | medium |
| — | Deployment environment without reviewers | L2 | `repo_environment:{name}` | collected | `github-repo-environment-without-reviewers` | medium |
| — | Unresolved secret-scanning alerts | L1 | `repo_open_secret_scanning_alerts` | collected | `github-repo-open-secret-scanning-alerts` | critical |
| — | Repository webhook without TLS verification | L2 | `repo_webhook:{id}` config | collected | `github-repo-webhook-tls-disabled` | high |
| — | Write-capable deploy key | L1 | `repo_deploy_key:{id}` | collected | `github-repo-writable-deploy-key` | high |
| — | Stale SSO-authorized credential | L2 | `sso_credential:{id}` last accessed | collected | `github-sso-credential-stale` | medium |
| — | Copilot public-code suggestions allowed | L2 | Copilot org policy | collected | `github-copilot-public-code-suggestions` | medium |
| — | Inactive Copilot seat | L2 | Copilot seat last activity | collected | `github-copilot-seat-inactive` | low |
| — | Custom repository role with broad permissions | L2 | custom repo role permissions | collected | `github-custom-repo-role-broad` | high |
| — | Public package published from a private repository | L2 | package visibility | collected | `github-public-package-from-private-repo` | medium |
| — | Approved fine-grained PAT with admin permissions | L2 | approved PAT permissions | collected | `github-approved-pat-admin-permissions` | high |
| — | New-repository security defaults off | L1 | org `*_for_new_repositories` settings | collected | `github-repo-security-defaults-off` | medium |

## Section 8 — Activity monitoring (audit log)

Event policies over the org audit log. Enterprise Cloud plus `read:audit_log`;
the family degrades visibly when either is absent.

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | GitHub App installed | mon | `event` oauth.app.install | collected | `github-activity-app-installed` | medium |
| — | Branch protection or ruleset removed | mon | `event` protection.remove | collected | `github-activity-branch-protection-disabled` | critical |
| — | Deploy key added | mon | `event` deploy_key.create | collected | `github-activity-deploy-key-created` | medium |
| — | Org admin privilege revoked | mon | `event` privilege.revoke | collected | `github-activity-privilege-revoked` | medium |
| — | Repository made public | mon | `event` repo.visibility | collected | `github-activity-repo-made-public` | high |
| — | SAML SSO configuration changed | mon | `event` sso.change | collected | `github-activity-sso-changed` | high |
| — | Org webhook created or reconfigured | mon | `event` webhook.create | collected | `github-activity-webhook-created` | medium |

## Framework mapping notes

- CIS GitHub v1.2.0 control IDs (e.g. `1.1.1`) map to `COMPLIANCE["cis"]` on each policy.
- SOC2 CC6.x and NIST CSF PR.AC-x used where CIS section mapping is indirect.
- Internal `custom` controls (`GH-01` … `GH-09`) remain for pack-local catalog entries.
