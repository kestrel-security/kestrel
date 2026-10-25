# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Findings list secondary labels for setting subjects are ``key = value``.
Object-valued settings (Okta policies roll their rules up into one dict)
used to print the Python repr: ``okta_policy:00p1 = {'name': 'Default
Policy', ...}``. A label never shows a dict or list repr."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from kestrel.db.models.finding import FindingSubjectType
from kestrel.findings.investigation import subject as subject_mod
from kestrel.findings.investigation.subject import display_setting_value, subject_label_for_list

_OKTA_POLICY = {
    "name": "Default Policy",
    "type": "OKTA_SIGN_ON",
    "status": "ACTIVE",
    "rules": [{"name": "Catch-all", "requires_mfa": False}],
}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "true"),
        (False, "false"),
        (30, "30"),
        ("strict", "strict"),
        (None, None),
        (_OKTA_POLICY, "Default Policy"),
        ({"display_name": "Corp IdP"}, "Corp IdP"),
        ({"enabled": True, "mode": "x"}, None),
        (["a", "b"], "a, b"),
        (["a", "b", "c", "d", "e"], "a, b, c +2 more"),
        ([{"x": 1}, {"y": 2}], "2 items"),
        ([], None),
    ],
)
def test_display_setting_value(value, expected):
    assert display_setting_value(value) == expected


def _list_label(monkeypatch, value):
    def fake_resolve(db, finding):
        return {
            "label": "Okta sign-on policy: Default Policy",
            "secondary": "okta_policy:00p1",
            "context": {"setting_value": value},
        }

    monkeypatch.setattr(subject_mod, "resolve_subject", fake_resolve)
    finding = SimpleNamespace(subject_type=FindingSubjectType.SETTING)
    return subject_label_for_list(None, finding)  # type: ignore[arg-type]


def test_an_okta_policy_setting_lists_the_policy_name_not_a_dict(monkeypatch):
    label, secondary = _list_label(monkeypatch, _OKTA_POLICY)

    assert label == "Okta sign-on policy: Default Policy"
    assert secondary == "okta_policy:00p1 = Default Policy"
    assert "{" not in secondary
    assert "[" not in secondary


def test_an_unnamed_object_setting_shows_just_the_key(monkeypatch):
    _, secondary = _list_label(monkeypatch, {"enabled": True, "nested": {"a": 1}})

    assert secondary == "okta_policy:00p1"


def test_a_scalar_setting_keeps_key_equals_value(monkeypatch):
    _, secondary = _list_label(monkeypatch, False)

    assert secondary == "okta_policy:00p1 = false"
