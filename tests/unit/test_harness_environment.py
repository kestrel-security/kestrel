# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The harness sets the test environment before `kestrel` is imported.

If these fail, the suite pays again at runtime for the per-batch interpreter
startup the harness exists to avoid -- or, worse, a test process is installing
a global OpenTelemetry provider and binding a metrics port.
"""

from __future__ import annotations

import os

from kestrel.auth.passwords import hash_password, verify_password
from kestrel.observability.startup import observability_enabled


def test_observability_is_disabled_in_test_processes():
    assert observability_enabled() is False


def test_policy_runtime_defaults_to_restricted():
    # The 5.2x lever. Tests that need the subprocess runtime's isolation
    # contract set it themselves; the bulk suite must not pay for a fresh
    # interpreter per evaluation batch.
    assert os.environ["KESTREL_POLICY_RUNTIME"] == "restricted"


def test_argon2_runs_at_test_cost():
    assert os.environ["KESTREL_ARGON2_TIME_COST"] == "1"
    assert os.environ["KESTREL_ARGON2_MEMORY_COST"] == "8"
    assert os.environ["KESTREL_ARGON2_PARALLELISM"] == "1"


def test_password_hashing_still_round_trips_at_test_cost():
    # Cheap parameters are only acceptable if they are still real Argon2id.
    digest = hash_password("correct-horse-battery-staple")
    assert digest.startswith("$argon2id$")
    assert verify_password("correct-horse-battery-staple", digest)
    assert not verify_password("wrong-password-entirely", digest)


def test_a_master_key_is_available_without_reading_the_developers_dotenv():
    import base64

    from kestrel.secrets.crypto import KEY_SIZE_BYTES

    assert len(base64.b64decode(os.environ["KESTREL_MASTER_KEY"])) == KEY_SIZE_BYTES


def test_this_tier_is_marked_unit(request):
    # The marker comes from tests/unit/conftest.py, not from this file.
    assert request.node.get_closest_marker("unit") is not None
