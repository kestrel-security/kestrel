# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-network-zone-matches-everything"
TITLE = "Okta policy network zones that admit every address"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A policy zone containing 0.0.0.0/0 or ::/0 matches the entire internet, so a rule scoped to it "
    "applies everywhere while appearing to be a network control."
)
REMEDIATION = "Narrow the zone to the ranges it is meant to cover, or remove the rules that depend on it."
REQUIRES = ["okta:network_zones"]
COMPLIANCE = {"soc2": ["CC6.6"], "nist_csf": ["PR.AC-5"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    if not str(setting.get("key") or "").startswith("okta_network_zone:"):
        return True
    if str(value.get("usage") or "").upper() != "POLICY":
        return True
    return value.get("matches_everything") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value")
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.label": setting.get("label"),
        "setting.value": value,
        "application.name": application.get("name"),
    }
