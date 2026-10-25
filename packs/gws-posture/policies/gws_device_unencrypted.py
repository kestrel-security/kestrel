# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-device-unencrypted"
TITLE = "Google Workspace enrolled mobile device is not encrypted"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "A mobile device enrolled in Google Workspace MDM reports an unencrypted storage state. "
    "If the device is lost or stolen, corporate data is accessible without authentication."
)
REMEDIATION = (
    "Require encryption in your MDM policy. For Android, enable full-disk or file-based "
    "encryption via the device policy in Google Admin console → Devices → Mobile device "
    "management. For iOS, encryption is automatic when a passcode is set."
)
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["PR.DS-1"]}
REQUIRES = ["google_workspace:devices"]


def policy(resource):
    application = resource.get("application") or {}
    obj = resource.get("resource") or {}
    if application.get("type") != "google_workspace":
        return True
    if obj.get("resource_type") != "device":
        return True
    if obj.get("management_type") != "mdm":
        return True
    return bool(obj.get("encrypted", True))


def evidence(resource):
    obj = resource.get("resource") or {}
    application = resource.get("application") or {}
    return {
        "device.name": obj.get("name"),
        "device.owner_email": obj.get("owner_email"),
        "device.type": obj.get("device_type"),
        "device.os": obj.get("os"),
        "device.encrypted": obj.get("encrypted"),
        "application.name": application.get("name"),
    }
