# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Slack's ``enterprise_id`` is only meaningful for Enterprise Grid org-level
user tokens. A workspace bot token has no E… id to give, so the create form
must not demand one, and collection must still run without it (Grid families
degrade and are recorded as skips, the same as any other gated family).
When the token is evidently org-level but no ``enterprise_id`` is set,
Test connection says so."""

from __future__ import annotations

import pytest
from kestrel.connectors.sdk.manifest import AuthMethodSpec
from kestrel_connector_slack.client import SlackClient
from kestrel_connector_slack.connector import SlackConnector
from kestrel_connector_slack.fixture_transport import ENTERPRISE_ID, TEAM_ID, build_fixture_transport
from kestrel_connector_slack.health import check_health
from pydantic import ValidationError


def test_slack_declares_enterprise_id_as_an_optional_config_field() -> None:
    method = SlackConnector.manifest.auth_method("oauth")
    assert method is not None
    assert "enterprise_id" in method.config_fields
    assert method.optional_config_fields == ["enterprise_id"]
    assert method.required_config_fields() == ["team_id"]


def test_optional_config_fields_must_be_declared_config_fields() -> None:
    with pytest.raises(ValidationError, match="optional_config_fields"):
        AuthMethodSpec(id="x", label="x", config_fields=["team_id"], optional_config_fields=["enterprise_id"])


def test_collection_without_enterprise_id_still_collects() -> None:
    connector = SlackConnector()
    connector.configure({"team_id": TEAM_ID})
    collector = connector.build_collector(build_fixture_transport())

    counts = {object_type: len(list(collector.collect(object_type))) for object_type in collector.discover()}

    assert counts["user"] > 0
    assert counts["usergroup"] > 0
    assert counts["team"] == 1


def _grid_client(enterprise_id: str | None) -> SlackClient:
    return SlackClient(build_fixture_transport(), team_id=TEAM_ID, enterprise_id=enterprise_id)


def test_health_check_says_when_a_grid_token_has_no_enterprise_id() -> None:
    result = check_health(_grid_client(None))

    assert result.healthy
    assert "enterprise_id" in result.message
    assert "Enterprise Grid" in result.message


def test_health_check_has_no_enterprise_notice_once_enterprise_id_is_set() -> None:
    result = check_health(_grid_client(ENTERPRISE_ID))

    assert result.healthy
    assert "enterprise_id" not in result.message
