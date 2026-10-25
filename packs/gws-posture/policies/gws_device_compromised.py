# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-device-compromised"
TITLE = "Google Workspace enrolled device is marked Compromised"
SEVERITY = "critical"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "A mobile device enrolled in Google Workspace MDM has a compromised status. "
    "A compromised device may have a modified OS (root/jailbreak), tampered apps, "
    "or detected malware. Corporate data on this device should be treated as exposed."
)
REMEDIATION = (
    "In Google Admin console → Devices → Mobile devices, review the device, revoke "
    "its access, and perform a remote wipe if the user confirms it is compromised. "
    "Require the user to re-enroll from a clean device."
)
COMPLIANCE = {"soc2": ["CC6.6"], "nist_csf": ["DE.CM-7"]}
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
    return not bool(obj.get("compromised"))


def evidence(resource):
    obj = resource.get("resource") or {}
    application = resource.get("application") or {}
    return {
        "device.name": obj.get("name"),
        "device.owner_email": obj.get("owner_email"),
        "device.type": obj.get("device_type"),
        "device.os": obj.get("os"),
        "device.status": obj.get("status"),
        "device.compromised": obj.get("compromised"),
        "application.name": application.get("name"),
    }
