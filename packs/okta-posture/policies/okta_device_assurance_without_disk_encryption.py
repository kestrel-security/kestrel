# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-device-assurance-without-disk-encryption"
TITLE = "Detect Okta device assurance policies that do not require disk encryption"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A device assurance policy is how Okta decides a device is trustworthy enough to sign in. "
    "One that does not require disk encryption lets a lost or stolen laptop keep its session "
    "tokens and cached credentials readable."
)
REMEDIATION = "Require full-disk encryption on this device assurance policy in Okta (Security -> Device assurance policies)."
COMPLIANCE = {"custom": ["OKTA-08"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"]}
REQUIRES = ["okta:authenticators"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if not str(setting.get("key") or "").startswith("okta_device_assurance:"):
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    required = value.get("disk_encryption")
    # Absent means the connector could not read it, which is not the same as
    # "not required" -- stay quiet rather than guess.
    if required is None:
        return True
    return bool(required)


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
    return {
        "setting.key": setting.get("key"),
        "policy.name": value.get("name"),
        "policy.platform": value.get("platform"),
        "policy.disk_encryption": value.get("disk_encryption"),
        "policy.screen_lock": value.get("screen_lock"),
        "application.name": application.get("name"),
    }
