# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- `kestrel secrets status` and `kestrel secrets rotate`, the
operator-facing side of master-key rotation (docs/deployment.md)."""

from __future__ import annotations

from kestrel.cli import secrets as secrets_cli
from kestrel.secrets.crypto import EnvKeyProvider
from kestrel.secrets.store import get_secrets, set_secret
from kestrel.testing import make_master_key
from kestrel.testing.factories import make_connector_instance, make_organization
from typer.testing import CliRunner

from tests.integration.test_worker_tasks import _BorrowedSession


def _seed(db_session, monkeypatch, old_key: str) -> tuple:
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="ghp_notarealtokenvalue",
        key_provider=EnvKeyProvider(old_key),
    )
    monkeypatch.setattr(secrets_cli, "get_sessionmaker", lambda: lambda: _BorrowedSession(db_session))
    return org, instance


def test_status_reports_rows_under_the_previous_key_and_exits_clean(db_session, monkeypatch):
    old_key, new_key = make_master_key(), make_master_key()
    _seed(db_session, monkeypatch, old_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY", new_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY_PREVIOUS", old_key)

    result = CliRunner().invoke(secrets_cli.app, ["status"])

    assert result.exit_code == 0, result.output
    assert "Stored secrets: 1" in result.output
    assert "previous (KESTREL_MASTER_KEY_PREVIOUS)" in result.output
    assert "run `kestrel secrets rotate`" in result.output


def test_status_exits_2_when_a_row_was_written_with_a_key_this_process_lacks(db_session, monkeypatch):
    old_key, new_key = make_master_key(), make_master_key()
    _seed(db_session, monkeypatch, old_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY", new_key)
    monkeypatch.delenv("KESTREL_MASTER_KEY_PREVIOUS", raising=False)

    result = CliRunner().invoke(secrets_cli.app, ["status"])

    assert result.exit_code == 2, result.output
    assert "UNKNOWN KEY" in result.output
    assert "KESTREL_MASTER_KEY_PREVIOUS" in result.output


def test_rotate_re_encrypts_under_the_new_key_and_status_is_then_green(db_session, monkeypatch):
    old_key, new_key = make_master_key(), make_master_key()
    org, instance = _seed(db_session, monkeypatch, old_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY", new_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY_PREVIOUS", old_key)

    dry = CliRunner().invoke(secrets_cli.app, ["rotate", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "Would re-encrypt 1 secret(s)" in dry.output

    result = CliRunner().invoke(secrets_cli.app, ["rotate"])
    assert result.exit_code == 0, result.output
    assert "Re-encrypted 1 secret(s)" in result.output
    assert "connector_secrets: 1" in result.output

    # Readable with the new key alone, i.e. after KESTREL_MASTER_KEY_PREVIOUS is unset.
    assert get_secrets(
        db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=EnvKeyProvider(new_key)
    ) == {"token": "ghp_notarealtokenvalue"}

    monkeypatch.delenv("KESTREL_MASTER_KEY_PREVIOUS")
    status = CliRunner().invoke(secrets_cli.app, ["status"])
    assert status.exit_code == 0, status.output
    assert "Every stored secret is under the current key." in status.output

    again = CliRunner().invoke(secrets_cli.app, ["rotate", "--if-needed"])
    assert again.exit_code == 0, again.output
    assert again.output.strip() == ""


def test_rotate_exits_1_and_names_rows_it_cannot_read(db_session, monkeypatch):
    old_key, new_key = make_master_key(), make_master_key()
    _seed(db_session, monkeypatch, old_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY", new_key)
    monkeypatch.delenv("KESTREL_MASTER_KEY_PREVIOUS", raising=False)

    result = CliRunner().invoke(secrets_cli.app, ["rotate"])

    assert result.exit_code == 1, result.output
    assert "could not be re-encrypted" in result.output
    assert "UnknownKeyVersionError" in result.output


def test_commands_fail_clearly_without_a_master_key(db_session, monkeypatch):
    monkeypatch.delenv("KESTREL_MASTER_KEY", raising=False)
    monkeypatch.delenv("KESTREL_MASTER_KEY_PREVIOUS", raising=False)

    result = CliRunner().invoke(secrets_cli.app, ["status"])

    assert result.exit_code == 1, result.output
    assert "KESTREL_MASTER_KEY is not set" in result.output
