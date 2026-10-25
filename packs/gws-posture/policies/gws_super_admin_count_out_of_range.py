# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-super-admin-count-out-of-range"
TITLE = "Google Workspace Super Admin count is outside the 2–8 range"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "CISA SCuBA requires between 2 and 8 Super Admins (GWS.COMMONCONTROLS.6.2v1). "
    "Fewer than 2 is a business continuity risk (no backup if the only admin is locked out). "
    "More than 8 increases the attack surface unnecessarily."
)
REMEDIATION = (
    "Review Super Admin assignments in Google Admin console → Account → Admin roles → "
    "Super Admin. Remove excess accounts and add break-glass accounts if fewer than two exist. "
    "Non-admin tasks should use delegated roles (Help Desk Admin, Groups Admin, etc.)."
)
COMPLIANCE = {"cisa": ["GWS-06"], "soc2": ["CC6.2"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:org_settings", "google_workspace:grants"]

MIN_ADMINS = 2
MAX_ADMINS = 8


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "super_admin_count":
        return True
    count = int(setting.get("value") or 0)
    return MIN_ADMINS <= count <= MAX_ADMINS


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "super_admin_count": setting.get("value"),
        "min_allowed": MIN_ADMINS,
        "max_allowed": MAX_ADMINS,
        "application.name": application.get("name"),
    }
