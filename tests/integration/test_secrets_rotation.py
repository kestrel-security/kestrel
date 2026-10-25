# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- master-key rotation re-encrypts every stored secret.

Seeds one row in each of the six secret-bearing tables under key A through
the real authoring helpers, then rotates to key B and proves every helper
reads its secret back with B alone. Also pins the list of locations to the
schema, so a new ciphertext column cannot be added without joining the
rotation.
"""

from __future__ import annotations

import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kestrel.auth import mfa
from kestrel.db.base import Base
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.connector import ConnectorSecret
from kestrel.notifications.smtp_settings import SECURITY_STARTTLS, upsert_org_smtp_settings
from kestrel.policies.llm_settings import LLM_PROVIDERS, resolve_llm_credentials, upsert_org_llm_settings
from kestrel.secrets.crypto import LEGACY_KEY_VERSION, NONCE_SIZE_BYTES, EnvKeyProvider, key_id
from kestrel.secrets.rotation import ROTATION_AUDIT_ACTION, SECRET_LOCATIONS, rotate_all, rotation_status
from kestrel.secrets.store import get_secrets, set_secret
from kestrel.testing import make_master_key
from kestrel.testing.factories import make_connector_instance, make_operator, make_organization
from kestrel.ticketing.authoring import create_integration, decrypt_integration_token
from kestrel.webhooks.authoring import create_endpoint, decrypt_endpoint_secret
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.integration.test_worker_tasks import _BorrowedSession


def _b64_to_bytes(key_b64: str) -> bytes:
    import base64

    return base64.b64decode(key_b64)


def _seed_everything(db_session: Session, provider: EnvKeyProvider):
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="t0k",
        key_provider=provider,
    )
    endpoint, signing_secret = create_endpoint(
        db_session, org_id=org.id, name="Hooks", url="https://1.1.1.1/hook", events=["finding.opened"], key_provider=provider
    )
    integration = create_integration(
        db_session,
        org_id=org.id,
        name="Issues",
        provider="github_issues",
        api_token="ghp_notarealtokenvalue",
        config={"repo": "acme/security"},
        key_provider=provider,
    )
    llm_provider = sorted(LLM_PROVIDERS)[0]
    upsert_org_llm_settings(
        db_session, org_id=org.id, provider=llm_provider, api_key="sk-not-a-real-key-0001", key_provider=provider
    )
    operator = make_operator(db_session, org)
    totp_secret, _uri = mfa.start_enrolment(operator, key_provider=provider)
    upsert_org_smtp_settings(
        db_session,
        org_id=org.id,
        host="127.0.0.1",
        port=587,
        security=SECURITY_STARTTLS,
        from_address="kestrel@example.com",
        username="mailer",
        password="mail-pass",
        key_provider=provider,
    )
    db_session.flush()
    return org, instance, endpoint, signing_secret, integration, operator, totp_secret


def _assert_everything_reads(db_session: Session, seeded, provider: EnvKeyProvider) -> None:
    org, instance, endpoint, signing_secret, integration, operator, totp_secret = seeded
    assert get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider) == {
        "token": "t0k"
    }
    assert decrypt_endpoint_secret(endpoint, key_provider=provider) == signing_secret
    assert decrypt_integration_token(integration, key_provider=provider) == "ghp_notarealtokenvalue"
    creds = resolve_llm_credentials(db_session, org.id, key_provider=provider)
    assert creds is not None
    assert creds.api_key == "sk-not-a-real-key-0001"
    assert mfa._secret(operator, provider) == totp_secret
    from kestrel.notifications.smtp_settings import _org_config, get_org_smtp_settings

    config = _org_config(get_org_smtp_settings(db_session, org.id), provider)
    assert config is not None
    assert config.password == "mail-pass"


def test_rotate_moves_every_table_to_the_new_key_and_the_old_key_is_no_longer_needed(db_session: Session):
    old_key, new_key = make_master_key(), make_master_key()
    seeded = _seed_everything(db_session, EnvKeyProvider(old_key))
    org = seeded[0]
    rotating = EnvKeyProvider(new_key, previous_key_b64=old_key)
    _assert_everything_reads(db_session, seeded, rotating)

    before = rotation_status(db_session, rotating)
    assert before.total_rows == 6
    assert before.stale_rows == 6
    assert before.unreadable_rows == 0
    assert set(before.rows_by_table) == {location.table for location in SECRET_LOCATIONS}

    report = rotate_all(_BorrowedSession(db_session), rotating)  # type: ignore[arg-type]

    assert report.failed == []
    assert report.rotated == 6
    assert set(report.rotated_by_table) == {location.table for location in SECRET_LOCATIONS}
    after = rotation_status(db_session, rotating)
    assert after.stale_rows == 0
    assert after.rows_by_key_version == {key_id(_b64_to_bytes(new_key)): 6}

    for row in db_session.scalars(select(ConnectorSecret)).all():
        db_session.refresh(row)
    _assert_everything_reads(db_session, seeded, EnvKeyProvider(new_key))

    audit = db_session.scalars(select(AuditLog).where(AuditLog.action == ROTATION_AUDIT_ACTION)).all()
    assert [row.org_id for row in audit] == [org.id]
    assert audit[0].context["rows"] == {location.table: 1 for location in SECRET_LOCATIONS}


def test_rotate_is_idempotent_and_skips_rows_already_current(db_session: Session):
    key = make_master_key()
    provider = EnvKeyProvider(key)
    _seed_everything(db_session, provider)

    report = rotate_all(_BorrowedSession(db_session), provider)  # type: ignore[arg-type]

    assert report.rotated == 0
    assert report.failed == []
    assert rotation_status(db_session, provider).stale_rows == 0


def test_dry_run_counts_but_writes_nothing(db_session: Session):
    old_key, new_key = make_master_key(), make_master_key()
    seeded = _seed_everything(db_session, EnvKeyProvider(old_key))
    rotating = EnvKeyProvider(new_key, previous_key_b64=old_key)
    instance = seeded[1]
    before = db_session.scalars(select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id)).one()
    ciphertext_before, version_before = before.ciphertext, before.key_version

    report = rotate_all(db_session, rotating, dry_run=True)

    assert report.dry_run is True
    assert report.rotated == 6
    db_session.refresh(before)
    assert (before.ciphertext, before.key_version) == (ciphertext_before, version_before)
    assert rotation_status(db_session, rotating).stale_rows == 6
    assert db_session.scalars(select(AuditLog).where(AuditLog.action == ROTATION_AUDIT_ACTION)).all() == []


def test_legacy_rows_without_associated_data_are_upgraded(db_session: Session):
    """What the 0.4.0 migration leaves behind: version 0, no context bound."""
    key = make_master_key()
    provider = EnvKeyProvider(key)
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    row = set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="x",
        key_provider=provider,
    )
    nonce = os.urandom(NONCE_SIZE_BYTES)
    row.ciphertext = AESGCM(provider.get_data_key(org.id)).encrypt(nonce, b"pre-0.4", None)
    row.nonce = nonce
    row.key_version = LEGACY_KEY_VERSION
    db_session.flush()
    assert get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider) == {
        "token": "pre-0.4"
    }
    assert rotation_status(db_session, provider).legacy_rows == 1

    report = rotate_all(_BorrowedSession(db_session), provider)  # type: ignore[arg-type]

    assert report.rotated == 1
    assert report.failed == []
    db_session.refresh(row)
    assert row.key_version == provider.current_key_version
    assert get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider) == {
        "token": "pre-0.4"
    }
    assert rotation_status(db_session, provider).legacy_rows == 0


def test_a_row_under_an_unknown_key_is_reported_and_left_alone(db_session: Session):
    lost_key, key = make_master_key(), make_master_key()
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="x",
        key_provider=EnvKeyProvider(lost_key),
    )
    provider = EnvKeyProvider(key)
    assert rotation_status(db_session, provider).unreadable_rows == 1

    report = rotate_all(_BorrowedSession(db_session), provider)  # type: ignore[arg-type]

    assert report.rotated == 0
    assert len(report.failed) == 1
    assert report.failed[0].table == "connector_secrets"
    assert "UnknownKeyVersionError" in report.failed[0].error
    assert rotation_status(db_session, provider).unreadable_rows == 1


def test_secret_locations_cover_every_ciphertext_column_in_the_schema():
    """A new ``*_nonce`` column must come with a key-version column and a
    ``SECRET_LOCATIONS`` entry, or rotation would silently skip it."""
    expected: set[tuple[str, str, str]] = set()
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if not column.name.endswith("nonce"):
                continue
            prefix = column.name.removesuffix("nonce").rstrip("_")
            ciphertext = f"{prefix}_ciphertext" if prefix else "ciphertext"
            version = f"{prefix}_key_version" if prefix else "key_version"
            assert ciphertext in table.c, f"{table.name}.{column.name} has no matching ciphertext column"
            assert version in table.c, f"{table.name}.{column.name} has no matching key-version column"
            expected.add((table.name, ciphertext, version))

    covered = {(loc.table, loc.ciphertext_attr, loc.key_version_attr) for loc in SECRET_LOCATIONS}
    assert covered == expected
    assert len({loc.table for loc in SECRET_LOCATIONS}) == 6


def test_every_location_builds_a_distinct_context_for_the_same_row_id():
    row_id = uuid.uuid4()

    class _Row:
        id = row_id
        field_name = "token"

    contexts = {location.context(_Row()) for location in SECRET_LOCATIONS}
    assert len(contexts) == len(SECRET_LOCATIONS)
