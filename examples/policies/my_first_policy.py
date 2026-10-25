# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "my-first-policy"
TITLE = "Identities without MFA"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Identities without MFA"
REMEDIATION = "Require MFA."


def policy(resource):
    identity = resource.get("identity") or {}
    return bool(identity.get("mfa_enabled"))
