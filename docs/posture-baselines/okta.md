# Okta posture baseline matrix

**Vendor baselines:** DISA Okta IDaaS STIG, Okta security best practices  
**Supplement:** NIST SP 800-63B (authenticators), NIST SP 800-53 Rev 5

Profile levels: **L1** = STIG CAT I / essential, **L2** = STIG CAT II, **mon** = activity monitor

## Section 1 — Authentication & MFA

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| STIG V-OKTA-0001 | MFA enrollment required | L1 | `tenant_setting.mfa_enroll_policy_required` (from the MFA_ENROLL policy; `GET /api/v1/org` carries no security configuration) | collected | `okta-mfa-enroll-not-required` | high |
| STIG V-OKTA-0002 | Privileged admin without MFA | L1 | identity roles + mfa_enabled | collected | `okta-admin-without-mfa` | critical |
| STIG V-OKTA-0003 | Phishing-resistant authenticators required | L2 | authenticator catalog | collected | `okta-no-phishing-resistant-authenticator` | high |
| 800-63B AAL2 | Password + MFA for admins | L1 | user factors | collected | `okta-admin-without-mfa` | critical |

## Section 2 — Identity lifecycle

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| STIG V-OKTA-0010 | Disabled user retains admin role | L1 | identity.is_disabled + roles | collected | `okta-disabled-privileged-admin` | critical |
| STIG V-OKTA-0011 | Dormant privileged admin (>90d) | L1 | identity.last_active_at | collected | `okta-dormant-admin` | high |
| STIG V-OKTA-0012 | Unused API token (>180d) | L1 | api token last_active_at | collected | `okta-api-token-unused` | high |

## Section 3 — Password & session

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| STIG V-OKTA-0020 | Password min length ≥12 | L1 | password_policy.password_min_length | collected | `okta-password-policy-weak` | medium |
| STIG V-OKTA-0021 | Password complexity enforced | L2 | `password_complexity.excludeUsername` | collected | `okta-password-allows-username` | medium |
| STIG V-OKTA-0022 | Session lifetime bounded | L2 | global session policy rules | collected | `okta-session-lifetime-excessive`, `okta-session-never-expires` | medium |
| STIG V-OKTA-0023 | Network zone restrictions for admin | L2 | network zones + sign-on policies | collected | `okta-policy-rule-without-mfa` | high |
| — | Super Admin count outside 2–8 | L2 | role assignment counts | collected | `okta-super-admin-count-out-of-range` | medium |

## Section 4 — Applications & SSO

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| STIG V-OKTA-0030 | No bookmark/SWA apps for sensitive apps | L1 | app sign_on_mode | collected | `okta-app-bookmark-or-swa` | medium |
| STIG V-OKTA-0031 | Sign-on policy requires MFA | L2 | authentication policy rules | collected | `okta-policy-rule-without-mfa` | high |

## Section 5 — Threat detection

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| STIG V-OKTA-0040 | Threat Insight enabled | L1 | `tenant_setting.threat_insight_enabled` | collected | `okta-threat-insight-disabled` | medium |
| STIG V-OKTA-0041 | Behavior detection enabled | L2 | behavior settings | collected | `okta-behaviors-disabled` | medium |
| — | No System Log stream configured | L2 | log streams inventory | collected | `okta-no-log-stream` | medium |
| — | Authorization server token lifetime excessive | L2 | auth server policies | collected | `okta-auth-server-long-token-lifetime` | medium |
| — | Authorization server wildcard scope | L2 | auth server scopes | collected | `okta-auth-server-wildcard-scope` | high |

## Section 6 — Activity monitoring

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Privilege grant in System Log | mon | event privilege.grant | collected | `okta-activity-privilege-grant` | high |
| — | MFA factor deactivated | mon | event mfa.disable | collected | `okta-activity-mfa-disabled` | critical |
| — | Threat detected | mon | event threat.detected | collected | `okta-activity-threat-detected` | critical |
| — | API token created | mon | event api.token.create | collected | `okta-activity-api-token-created` | high |
| — | Privileged role revoked | mon | event privilege.revoke | collected | `okta-activity-privilege-revoked` | medium |
| — | Okta support impersonation | mon | event support.access | collected | `okta-activity-impersonation` | critical |
| — | Policy rule weakened | mon | event policy.change | collected | `okta-activity-policy-weakening` | high |
| — | Network zone changed | mon | event config.change | collected | `okta-activity-zone-change` | medium |

## Section 7 — Perimeter and automation (Kestrel controls)

Not enumerated by the DISA Okta STIG. Shipped checks over collected data.

| Control | Title | Profile | Required data | Status | POLICY_ID | Severity |
|---------|-------|---------|---------------|--------|-----------|----------|
| — | Hook endpoint over plain HTTP | L1 | `okta_event_hook:{id}` / `okta_inline_hook:{id}` | collected | `okta-hook-endpoint-plaintext` | critical |
| — | Identity provider auto-provisions accounts | L2 | `okta_identity_provider:{id}` policy | collected | `okta-idp-auto-provisions-users` | high |
| — | Network zone admits every address | L2 | `okta_network_zone:{id}` gateways | collected | `okta-network-zone-matches-everything` | medium |
| — | Self-service registration enabled | L2 | `okta_policy:{id}` profile enrollment | collected | `okta-self-service-registration-enabled` | medium |
| — | Trusted origin over plain HTTP | L1 | `okta_trusted_origin:{id}` origin | collected | `okta-trusted-origin-plaintext` | high |
| — | Device assurance policy does not require disk encryption | L2 | `okta_device_assurance:{id}` disk_encryption | collected | `okta-device-assurance-without-disk-encryption` | medium |

## Framework mapping notes

- STIG rule IDs map to `COMPLIANCE["custom"]` with `OKTA-xx` pack catalog entries until DISA IDs are fully enumerated per policy.
- V-OKTA-0021 is implemented as username screening, not as a composition rule.
  Okta returns the whole complexity object, so a "requires a symbol" check is
  buildable — NIST SP 800-63B argues against shipping one, and asks for
  screening against context-specific words instead. The row is `collected`
  because the data is collected and a check reads it, not because every
  sub-clause of the STIG rule is asserted.
- NIST 800-53 controls (IA-2, AC-2, AC-6) referenced in `COMPLIANCE["nist_csf"]` where applicable.
- No CIS benchmark exists for Okta — do not claim CIS Foundations completeness.
