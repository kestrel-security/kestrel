# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the fast in-process runtime is for first-party packs only.

`kestrel demo` opts pack policies into the in-process runtime for speed. A
custom policy in the same org once inherited it too, so a policy that loops
forever hung `demo up` indefinitely. Custom policies must keep the subprocess
runtime's limits whatever the pack setting says.
"""

from __future__ import annotations

import time

import pytest
from kestrel.db.models.policy import PolicyEvaluationStatus, PolicyVersion
from kestrel.findings.pipeline import evaluate_policy_version
from kestrel.policies.authoring import create_custom_policy
from kestrel.policies.runtime import factory
from kestrel.testing.factories import make_organization

from tests.integration.test_api_factories import make_identity

_LOOPING_POLICY = """\
POLICY_ID = "loops-forever"
TITLE = "Loops forever"
SEVERITY = "low"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Never returns."
REMEDIATION = "n/a"

def policy(resource):
    while True:
        pass
"""


@pytest.fixture
def pack_runtime_in_process(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KESTREL_POLICY_RUNTIME", "subprocess")
    monkeypatch.setenv("KESTREL_PACK_POLICY_RUNTIME", "restricted")
    monkeypatch.setenv("KESTREL_POLICY_EVAL_TIMEOUT_SECONDS", "1")
    factory.reset_default_runtime()
    yield
    factory.reset_default_runtime()


def test_a_looping_custom_policy_still_times_out(db_session, pack_runtime_in_process):
    org = make_organization(db_session)
    make_identity(db_session, org)
    policy = create_custom_policy(db_session, org_id=org.id, source_text=_LOOPING_POLICY, created_by="test")
    version = db_session.get(PolicyVersion, policy.current_version_id)

    started = time.monotonic()
    evaluation = evaluate_policy_version(db_session, version, org.id)

    assert evaluation.status is PolicyEvaluationStatus.ERROR
    assert time.monotonic() - started < 15
