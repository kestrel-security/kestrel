# Kestrel connector: Google Workspace

Collects Google Workspace directory users, groups, admin role assignments,
shared drive access, Cloud Identity Policy API settings (OU-scoped),
mobile/ChromeOS devices, Alert Center alerts, inbound SAML SSO, Admin Reports
activity feeds, and domain-wide delegation clients reconstructed from admin
audit into Kestrel's normalized model.

**Status:** fixture-first for CI/demos; **live service-account JWT** with
visible degradation for every optional family. Admin Reports, Policy API,
devices, and Alert Center skip cleanly when the delegated admin lacks the
matching privilege. A live Test → Sync → Explore smoke on a real tenant, with
the full domain-wide delegation scope list authorized, is still open.

## Why this connector exists

It is the second connector, and the first real test of whether the SDK's
abstractions generalize past GitHub. Workspace shapes GitHub does not have:

- **First-class admin roles.** Real roles (Super Admin, Help Desk Admin,
  custom roles) assigned through `roleAssignments` normalize to `grant`
  objects carrying a `role_ref`.
- **Group-granted resource access.** A shared drive can be granted to a
  group rather than a user.
- **OU-scoped security settings.** Cloud Identity Policy API returns 2SV,
  password, session, Drive sharing, Gmail, Marketplace, and related settings
  per organizational unit — subject-scoped `setting` rows.

## Object types

Core: `domain`, `domain_list`, `org_unit`, `user`, `group`, `group_member`,
`group_setting`, `admin_role`, `role_assignment`, `shared_drive`,
`drive_permission`, `user_token`, `login_activity`.

Depth (all optional / degrade visibly): `customer`, `policy`,
`mobile_device`, `chromeos_device`, `alert`, `inbound_sso_profile`,
`inbound_sso_assignment`, `admin_activity`, `drive_activity`,
`saml_activity`, `user_accounts_activity`, `groups_activity`,
`mobile_activity`, `dwd_client` (synthetic from admin audit).

**Honest limits:** per-user Gmail forwarding needs a mail-reading scope and
is not collected. Vault retention and context-aware access are edition-gated
and not collected on Business Starter/Standard.

## Fixture mode

```bash
uv run kestrel connector validate connectors/google_workspace
```

Fixtures describe a synthetic `acme.example.com` domain and include
deliberately interesting cases for the posture pack (weak 2SV on an OU,
compromised device, broad DWD client, external Drive sharing).

## Live mode

Full setup: [`docs/connectors/google-workspace-setup.md`](../../docs/connectors/google-workspace-setup.md).

Required scopes are declared in `manifest.yaml`. Alert Center uses
`apps.alerts` (no readonly variant); it is allowlisted in
`readonly_scopes.py` with the same honesty precedent as GitHub classic
`repo`. Prefer a Super Admin for the delegated subject.

## Authoring notes

See the Connector SDK docs and `docs/connectors.md` § The connector bar.
Every setting-producing field must be declared in `fixtures/PROVENANCE.yaml`.
