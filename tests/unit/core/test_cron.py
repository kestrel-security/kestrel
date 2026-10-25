# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.scheduling.cron.validate_cron`: 5-field cron expression validation
backing `ConnectorInstance.schedule_cron`.
"""

from __future__ import annotations

import pytest
from kestrel.scheduling.cron import InvalidCronError, validate_cron


@pytest.mark.parametrize(
    "expr",
    [
        "0 0 * * *",  # daily at midnight
        "*/15 * * * *",  # every 15 minutes
        "0 9-17 * * 1-5",  # business hours, weekdays
        "0 0 1 1 *",  # once a year
    ],
)
def test_valid_cron_expressions_are_accepted(expr):
    validate_cron(expr)  # must not raise


@pytest.mark.parametrize(
    "expr",
    [
        "",
        "not a cron expression",
        "* * * *",  # only four fields
        "60 * * * *",  # minute out of range
        "* * * 13 *",  # month out of range
        "* * * * 8",  # weekday out of range
    ],
)
def test_invalid_cron_expressions_are_rejected(expr):
    with pytest.raises(InvalidCronError):
        validate_cron(expr)


def test_the_error_message_names_the_offending_expression():
    with pytest.raises(InvalidCronError, match="not-a-cron-expr"):
        validate_cron("not-a-cron-expr")
