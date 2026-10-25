# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- a stored ciphertext only decrypts in the row it was written to.

Someone with write access to the database (a stolen dump is read-only, but a
compromised DBA account or an injection bug is not) could otherwise move a
ciphertext between rows: point a connector at a lower-value token, copy one
webhook's signing secret onto another, or give a victim's TOTP secret to an
account they control. Every ciphertext carries its table, row, and field as
AES-GCM associated data, so each of those moves fails to decrypt.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from kestrel.auth import mfa
from kestrel.db.models.connector import ConnectorSecret
from kestrel.secrets.crypto import LEGACY_KEY_VERSION, EnvKeyProvider
from kestrel.secrets.store import get_secrets, set_secret
from kestrel.testing import make_master_key
from kestrel.testing.factories import make_connector_instance, make_operator, make_organization
from kestrel.webhooks.authoring import create_endpoint, decrypt_endpoint_secret
from sqlalchemy import select
from sqlalchemy.orm import Session


def _connector_rows(db_session: Session, instance_id):
    rows = db_session.scalars(
        select(ConnectorSecret)
        .where(ConnectorSecret.connector_instance_id == instance_id)
        .order_by(ConnectorSecret.field_name)
    ).all()
    return {row.field_name: row for row in rows}


def test_connector_secrets_swapped_between_fields_fail_to_decrypt(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="t",
        key_provider=provider,
    )
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="client_secret",
        plaintext_value="c",
        key_provider=provider,
    )
    rows = _connector_rows(db_session, instance.id)
    assert get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider) == {
        "token": "t",
        "client_secret": "c",
    }

    a, b = rows["token"], rows["client_secret"]
    a.ciphertext, b.ciphertext = b.ciphertext, a.ciphertext
    a.nonce, b.nonce = b.nonce, a.nonce
    db_session.flush()

    with pytest.raises(InvalidTag):
        get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider)


def test_connector_secret_copied_to_another_instance_fails_to_decrypt(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    victim = make_connector_instance(db_session, org)
    attacker = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=victim.id,
        field_name="token",
        plaintext_value="prod",
        key_provider=provider,
    )
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=attacker.id,
        field_name="token",
        plaintext_value="mine",
        key_provider=provider,
    )
    source = _connector_rows(db_session, victim.id)["token"]
    target = _connector_rows(db_session, attacker.id)["token"]

    target.ciphertext, target.nonce, target.key_version = source.ciphertext, source.nonce, source.key_version
    db_session.flush()

    with pytest.raises(InvalidTag):
        get_secrets(db_session, org_id=org.id, connector_instance_id=attacker.id, key_provider=provider)
    # The victim's own row is untouched and still reads.
    assert get_secrets(db_session, org_id=org.id, connector_instance_id=victim.id, key_provider=provider) == {
        "token": "prod"
    }


def test_relabelling_a_connector_secrets_field_name_fails_to_decrypt(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    instance = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="t",
        key_provider=provider,
    )

    _connector_rows(db_session, instance.id)["token"].field_name = "client_secret"
    db_session.flush()

    with pytest.raises(InvalidTag):
        get_secrets(db_session, org_id=org.id, connector_instance_id=instance.id, key_provider=provider)


def test_marking_a_bound_row_legacy_does_not_bypass_the_binding(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    victim = make_connector_instance(db_session, org)
    attacker = make_connector_instance(db_session, org)
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=victim.id,
        field_name="token",
        plaintext_value="prod",
        key_provider=provider,
    )
    set_secret(
        db_session,
        org_id=org.id,
        connector_instance_id=attacker.id,
        field_name="token",
        plaintext_value="mine",
        key_provider=provider,
    )
    source = _connector_rows(db_session, victim.id)["token"]
    target = _connector_rows(db_session, attacker.id)["token"]

    target.ciphertext, target.nonce, target.key_version = source.ciphertext, source.nonce, LEGACY_KEY_VERSION
    db_session.flush()

    with pytest.raises(InvalidTag):
        get_secrets(db_session, org_id=org.id, connector_instance_id=attacker.id, key_provider=provider)


def test_a_webhook_signing_secret_copied_to_another_endpoint_fails_to_decrypt(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    a, secret_a = create_endpoint(
        db_session,
        org_id=org.id,
        name="A",
        url="https://1.1.1.1/hook",
        events=["finding.opened"],
        key_provider=provider,
    )
    b, _secret_b = create_endpoint(
        db_session,
        org_id=org.id,
        name="B",
        url="https://8.8.4.4/hook",
        events=["finding.opened"],
        key_provider=provider,
    )
    assert decrypt_endpoint_secret(a, key_provider=provider) == secret_a

    b.secret_ciphertext, b.secret_nonce, b.secret_key_version = a.secret_ciphertext, a.secret_nonce, a.secret_key_version
    db_session.flush()

    with pytest.raises(InvalidTag):
        decrypt_endpoint_secret(b, key_provider=provider)


def test_a_totp_secret_copied_to_another_operator_fails_to_decrypt(db_session: Session):
    provider = EnvKeyProvider(make_master_key())
    org = make_organization(db_session)
    victim = make_operator(db_session, org, email="victim@example.com")
    attacker = make_operator(db_session, org, email="attacker@example.com")
    victim_secret, _uri = mfa.start_enrolment(victim, key_provider=provider)
    mfa.start_enrolment(attacker, key_provider=provider)
    db_session.flush()
    assert mfa._secret(victim, provider) == victim_secret

    attacker.mfa_secret_ciphertext = victim.mfa_secret_ciphertext
    attacker.mfa_secret_nonce = victim.mfa_secret_nonce
    attacker.mfa_secret_key_version = victim.mfa_secret_key_version
    db_session.flush()

    with pytest.raises(InvalidTag):
        mfa._secret(attacker, provider)
