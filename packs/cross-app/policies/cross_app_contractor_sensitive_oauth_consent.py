# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-contractor-sensitive-oauth-consent"
TITLE = "Contractor or guest who authorized a third-party application with sensitive scopes"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This account belongs to a contractor, vendor, or guest and has consented to a third-party "
    "OAuth application that holds sensitive scopes (mail, files, directory, admin). A consented "
    "token keeps working after the engagement ends and after the account is disabled, and it "
    "reads company data under the contractor's access rather than under a reviewed integration."
)
REMEDIATION = (
    "Revoke the grants named in the evidence, and restrict third-party app consent for guest and "
    "contractor accounts to an allow list."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "cis": ["5.4"], "nist_csf": ["PR.AC-4"], "custom": ["XAPP-09"]}
REQUIRES = ["identity:worker_type", "identity:oauth_grants"]

CONTINGENT_WORKER_TYPES = ("contractor", "vendor_or_partner", "guest")


def policy(resource):
    """True = compliant. Evaluated per account; an unknown worker type passes."""
    if worker_type_of(resource) not in CONTINGENT_WORKER_TYPES:
        return True
    sensitive = [grant for grant in resource.get("oauth_grants") or [] if grant.get("sensitive_scope_names")]
    return not sensitive


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    sensitive = [grant for grant in resource.get("oauth_grants") or [] if grant.get("sensitive_scope_names")]
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "application.name": application.get("name"),
        "worker_type": worker_type_of(resource),
        "oauth_grants": [
            {
                "name": grant.get("oauth_application_name"),
                "publisher": grant.get("publisher"),
                "sensitive_scope_names": grant.get("sensitive_scope_names"),
                "last_used_at": grant.get("last_used_at"),
            }
            for grant in sensitive
        ],
    }
