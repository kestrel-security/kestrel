# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shipped test helpers for Kestrel and for connectors built against its SDK.

This package is part of the distributed ``kestrel`` wheel, not test-only code:
a third-party connector author gets the same ``RecordingTransport`` and row
factories Kestrel's own suite uses.

Deliberately free of ``pytest`` imports at module level -- nothing here is a
fixture, so importing ``kestrel.testing`` from application code, a script, or a
non-pytest runner works and does not drag a test framework into the runtime
dependency set. Wire these into ``conftest.py`` fixtures in your own suite.
"""

from kestrel.testing.api import api_client
from kestrel.testing.db import savepoint_session
from kestrel.testing.factories import (
    DEFAULT_PASSWORD,
    make_application,
    make_application_instance,
    make_connector,
    make_connector_instance,
    make_operator,
    make_organization,
)
from kestrel.testing.keys import MASTER_KEY_ENV_VAR, make_master_key
from kestrel.testing.transport import RecordingTransport, TransportPathNotFound

__all__ = [
    "DEFAULT_PASSWORD",
    "MASTER_KEY_ENV_VAR",
    "RecordingTransport",
    "TransportPathNotFound",
    "api_client",
    "make_application",
    "make_application_instance",
    "make_connector",
    "make_connector_instance",
    "make_master_key",
    "make_operator",
    "make_organization",
    "savepoint_session",
]
