# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for shared connector foundation helpers."""

from __future__ import annotations

from kestrel.connectors.activity_actions import (
    ACTION_CATEGORIES,
    NORMALIZED_ACTIONS,
    category_for,
)
from kestrel.connectors.settings_emit import alert_count_setting, setting_object
from kestrel.db.models.resource import ResourceType


def test_resource_type_includes_device() -> None:
    assert ResourceType.DEVICE.value == "device"


def test_normalized_actions_cover_depth_program_vocabulary() -> None:
    for action in (
        "policy.change",
        "config.change",
        "data.export",
        "device.enroll",
        "device.compromise",
        "support.access",
        "sso.change",
    ):
        assert action in NORMALIZED_ACTIONS
        assert category_for(action) != "other"
        assert ACTION_CATEGORIES[action]


def test_setting_object_subject_scoped() -> None:
    obj = setting_object(
        key="security.session_controls",
        category="security",
        label="Session length",
        value={"sessionLength": "12h"},
        value_type="object",
        subject_type="group",
        subject_ref="ou:engineering",
        provider_id_prefix="gws-policy",
    )
    assert obj.kind == "setting"
    assert obj.attributes["subject_type"] == "group"
    assert obj.attributes["subject_ref"] == "ou:engineering"
    assert obj.provider_id == "gws-policy:security.session_controls"


def test_alert_count_setting_is_security_integer() -> None:
    obj = alert_count_setting(
        key="open_critical_alerts",
        label="Open critical alerts",
        count=3,
        subject_type="resource",
        subject_ref="repo:acme/api",
    )
    assert obj.attributes["category"] == "security"
    assert obj.attributes["value"] == 3
    assert obj.attributes["value_type"] == "integer"
    assert obj.attributes["subject_ref"] == "repo:acme/api"
