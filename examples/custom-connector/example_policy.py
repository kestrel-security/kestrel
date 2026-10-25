# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "acme-widgets-user-without-mfa"
TITLE = "Example policy: detect Acme Widgets users without MFA"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Example policy: detect Acme Widgets users without MFA -- customize this for your real detection logic"
REMEDIATION = "Enable MFA for this user."


def policy(resource):
    identity = resource.get("identity") or {}
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
    }
