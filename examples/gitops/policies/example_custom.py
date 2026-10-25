# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "example-custom"
TITLE = "GitOps example: identities without MFA"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "GitOps example: identities without MFA"
REMEDIATION = "Require MFA for this identity."


def policy(resource):
    identity = resource.get("identity") or {}
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
    }
