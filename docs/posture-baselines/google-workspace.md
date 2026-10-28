# Google Workspace posture baseline matrix

**Vendor baseline:** CISA SCuBA Secure Configuration Baselines for Google Workspace
([cisagov/ScubaGoggles](https://github.com/cisagov/ScubaGoggles))
**Supplement:** CIS Google Workspace Benchmark, NIST CSF 1.1

Profile levels: **L1** = SCuBA *SHALL*, **L2** = SCuBA *SHOULD*, **mon** = activity monitor

Google Workspace is the one application Kestrel covers where an authoritative,
enumerable, publicly published baseline exists. That makes the ratio below
checkable by anyone, which is the point of publishing it — including while it is
unflattering.

**Where this stands.** SCuBA enumerates 28 controls in Common Controls alone and
17 more in Drive & Docs, plus eight further service baselines (Gmail beyond two
controls, Calendar, Chat, Meet, Sites, Classroom, Gemini, Assured Controls) that
are not yet mapped here. `packs/gws-posture` (pack version 0.2) ships 34 Workspace policies. The Cloud
Identity Policy API (`cloud-identity.policies.readonly`), collected since
connector manifest 0.2, unlocked most of the previously `needs-collection` configuration rows.

**Note:** the `policy` object type reads from the Cloud Identity Policy API,
which returns settings per-OU. The `gws-ou-*` policies fire at the OU level
and require `google_workspace:policy_settings` capability.

## Section 1 — Authentication (SCuBA Common Controls 1)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.COMMONCONTROLS.1.1v1 | Phishing-resistant MFA required for all users | L1 | Policy API: 2SV enforcement method | needs-collection | — | high |
| GWS.COMMONCONTROLS.1.2v1 | Alternative MFA enforced where phishing-resistant is unavailable | L1 | per-account `isEnforcedIn2Sv` | collected | `gws-2sv-not-enforced` | high |
| GWS.COMMONCONTROLS.1.2v1 | OU-level 2SV enforcement (Policy API) | L1 | Policy API: enforcement mode | collected | `gws-ou-2sv-not-enforced` | high |
| GWS.COMMONCONTROLS.1.3v1 | SMS or voice not used as an MFA method | L1 | Policy API: allowed 2SV methods | needs-collection | — | high |
| GWS.COMMONCONTROLS.1.4v1 | 2SV new-user enrollment period is 1–7 days | L2 | Policy API: enrollment grace period | collected | `gws-ou-2sv-long-grace` | medium |
| GWS.COMMONCONTROLS.1.5v1 | "Allow users to trust device" disabled | L2 | Policy API: device trust | needs-collection | — | medium |

## Section 2 — Privileged accounts (SCuBA Common Controls 6, 9)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.COMMONCONTROLS.6.1v1 | Admin accounts are cloud-only, separate from federated providers | L1 | identity + role assignment | collected | `gws-external-super-admin` | critical |
| GWS.COMMONCONTROLS.6.2v1 | Between two and eight super admins | L1 | role assignment counts | collected | `gws-super-admin-count-out-of-range` | medium |
| GWS.COMMONCONTROLS.9.1v1 | Highly privileged accounts enrolled in Advanced Protection | L2 | Policy API: APP enrollment | needs-collection | — | high |
| — | Super Admin not enrolled in 2SV | L1 | roles + `isEnrolledIn2Sv` | collected | `gws-super-admin-without-mfa` | high |
| — | Help Desk Admin not enrolled in 2SV | L1 | roles + `isEnrolledIn2Sv` | collected | `gws-help-desk-admin-without-mfa` | high |
| — | Groups Admin not enrolled in 2SV | L1 | roles + `isEnrolledIn2Sv` | collected | `gws-groups-admin-without-mfa` | high |
| — | Suspended or archived user still holds Super Admin | L1 | identity.is_disabled + roles | collected | `gws-disabled-super-admin` | critical |
| — | Suspended or archived user still holds Help Desk Admin | L1 | identity.is_disabled + roles | collected | `gws-disabled-help-desk-admin` | critical |

## Section 3 — Sessions, passwords and recovery (SCuBA Common Controls 4, 5, 8)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.COMMONCONTROLS.4.1v1 | Re-authentication after a 12-hour session | L1 | Policy API: session length | collected | `gws-session-too-long` | medium |
| GWS.COMMONCONTROLS.5.1v1 | Password strength enforced | L1 | Policy API: password policy | collected | `gws-password-policy-weak` | medium |
| GWS.COMMONCONTROLS.5.2v1 | Minimum password length of 12 | L1 | Policy API: password policy | collected | `gws-password-policy-weak` | medium |
| GWS.COMMONCONTROLS.5.5v1 | Passwords not reused | L2 | Policy API: password policy | needs-collection | — | low |
| GWS.COMMONCONTROLS.8.1v1 | Super admin self-recovery disabled | L1 | Policy API: account recovery | collected | `gws-super-admin-recovery-enabled` | high |
| GWS.COMMONCONTROLS.8.2v1 | User self-recovery disabled | L2 | Policy API: account recovery | needs-collection | — | medium |

## Section 4 — Third-party application access (SCuBA Common Controls 10, 11, 12)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.COMMONCONTROLS.10.1v1 | Third-party app access to Google services restricted | L1 | `user_token` scopes | collected | `gws-third-party-app-sensitive-scopes` | high |
| GWS.COMMONCONTROLS.10.2v1 | Users do not grant consent to low-risk OAuth scopes | L1 | per-user OAuth consents | collected | `gws-personal-consent-to-risky-app` | medium |
| GWS.COMMONCONTROLS.10.5v1 | Less secure app access prevented | L1 | Policy API: LSA setting | collected | `gws-less-secure-apps-allowed` | high |
| GWS.COMMONCONTROLS.11.1v1 | Only approved Marketplace applications installable | L1 | Policy API: Marketplace allowlist | collected | `gws-marketplace-unrestricted` | high |
| GWS.COMMONCONTROLS.12.1v1 | Google Takeout disabled | L2 | Policy API: Takeout setting | collected | `gws-takeout-enabled` | medium |
| — | Domain-wide delegation client holds sensitive scopes | L1 | admin audit → `dwd_client` | collected | `gws-dwd-client-broad-scopes` | high |

## Section 5 — Drive and Docs (SCuBA DRIVEDOCS)

SCuBA enumerates 17 controls here. Kestrel reads real Drive *permissions*, so
actual external exposure is detected; the domain-level sharing *configuration*
is now also collected via the Cloud Identity Policy API.

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.DRIVEDOCS.1.1v1 | External sharing restricted to allowlisted domains | L1 | Policy API: Drive sharing mode | collected | `gws-drive-external-sharing-enabled` | medium |
| GWS.DRIVEDOCS.1.5v1 | "Anyone with the link" disabled | L1 | Policy API: link sharing default | needs-collection | — | high |
| GWS.DRIVEDOCS.1.8v1 | New items default to private-to-owner | L2 | Policy API: default access | needs-collection | — | medium |
| GWS.DRIVEDOCS.4.1v1 | Drive SDK access disabled | L2 | Policy API: Drive SDK | needs-collection | — | medium |
| — | External identity has organizer access to a shared drive | L1 | `drive_permission` + identity.is_external | collected | `gws-shared-drive-admin-external` | high |
| — | Direct (non-group) admin grant on a shared drive | L2 | `drive_permission` granted_via | collected | `gws-direct-shared-drive-admin` | medium |
| — | Shared-drive admin not enrolled in 2SV | L1 | `drive_permission` + `isEnrolledIn2Sv` | collected | `gws-shared-drive-admin-without-mfa` | high |

## Section 6 — Groups (SCuBA GROUPS)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Group accepts members outside the Workspace domains | L1 | `group_allow_external_members` | collected | `gws-group-allows-external-members` | medium |
| — | Group membership is open to anyone with a Google account | L1 | `group_who_can_join` | collected | `gws-group-open-to-anyone` | high |
| — | Group accepts messages from outside the organization | L2 | `group_who_can_post_message` | collected | `gws-group-accepts-external-posts` | medium |
| GWS.GROUPS.1.1v1 | Group creation restricted to admins | L2 | Policy API: Groups for Business | needs-collection | — | low |

## Section 7 — Gmail (SCuBA GMAIL, partial)

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| GWS.GMAIL.4.1v1 | Auto-forwarding to external addresses disabled | L1 | Policy API: Gmail auto-forwarding | collected | `gws-gmail-autoforwarding-allowed` | high |
| GWS.GMAIL.5.1v1 | IMAP access disabled | L2 | Policy API: IMAP setting | needs-collection | — | low |

## Section 8 — Devices

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | MDM-enrolled device is compromised | L1 | mobile_device `deviceCompromisedStatus` | collected | `gws-device-compromised` | critical |
| — | MDM-enrolled device is not encrypted | L1 | mobile_device `encryptionStatus` | collected | `gws-device-unencrypted` | high |

## Section 9 — Activity monitoring

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Google flagged a suspicious sign-in or compromised account | mon | Reports `login` activity | collected | `gws-activity-suspicious-login` | high |
| — | 2-Step Verification turned off for an account | mon | Reports `login` activity, `2sv_disable` | collected | `gws-activity-two-step-disabled` | critical |
| — | Admin privilege granted to a user | mon | Reports `admin` activity | collected | `gws-activity-admin-privilege-grant` | high |
| — | SSO configuration changed | mon | Reports `admin` activity | collected | `gws-activity-sso-change` | high |
| — | Domain-wide delegation client authorized | mon | Reports `admin` activity | collected | `gws-activity-dwd-grant` | high |

## SCuBA baselines not yet mapped

Gmail (fully), Calendar, Chat, Meet, Sites, Classroom, Gemini, and Assured
Controls have published SCuBA baselines and **no rows here at all**. They are
not marked `not-collectable`, because that would claim they had been assessed
and found unreachable. They have not been assessed.

## Remaining not-collectable items

The following controls require access that Kestrel does not collect and that
the APIs do not expose in a machine-readable form:
- Advanced Protection Program enrollment (requires Google Vault admin API or manual check)
- Per-user Gmail forwarding filter enumeration (no bulk API)
- Client-side encryption (CAA) status per-user

## Framework mapping notes

- Rows with a `—` control are Kestrel checks with no SCuBA equivalent, mostly
  privileged-identity and real-permission checks that a configuration baseline
  does not express.
- `cisa` control ids in `packs/gws-posture` (`GWS-xx`) are pack-local catalog
  entries, not SCuBA control ids. They predate this matrix and should be
  reconciled with the `GWS.*` ids above.
- **Policy API note:** The Cloud Identity Policy API (`cloud-identity.policies.readonly`)
  was added. It delivers OU-scoped settings and unlocked most `needs-collection`
  rows in sections 1, 3, 4, 5, and 7. Settings are stored as `value_type=object`
  (the full `setting.value` dict) so policy functions can read provider-specific
  field names without a normalizer change.
