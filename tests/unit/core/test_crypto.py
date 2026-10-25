# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Envelope encryption (`kestrel.secrets.crypto`): round-trip, wrong-key
failure, per-org isolation via HKDF, context binding, and key rotation.

See docs/adr/0004-secrets-storage-and-encryption.md. `EnvKeyProvider` derives
a per-org data key from `KESTREL_MASTER_KEY` via HKDF using the org id as
salt; every ciphertext is also bound to its (table, row, field) through GCM
associated data and stamped with the id of the key that wrote it. These tests
assert that each of those bindings actually rejects, by AES-GCM's
authentication tag, rather than "silently produce garbage."
"""

from __future__ import annotations

import base64
import uuid

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kestrel.secrets.crypto import (
    LEGACY_KEY_VERSION,
    NONCE_SIZE_BYTES,
    EnvKeyProvider,
    MissingMasterKeyError,
    UnknownKeyVersionError,
    decrypt_secret,
    encrypt_secret,
    key_id,
    secret_context,
)
from kestrel.testing import make_master_key

ROW = uuid.UUID("00000000-0000-0000-0000-000000000001")
CTX = secret_context("connector_secrets", ROW, "token")


def _legacy_ciphertext(provider: EnvKeyProvider, org_id: uuid.UUID, plaintext: str) -> tuple[bytes, bytes]:
    """What pre-0.4.0 code wrote: no associated data."""
    import os

    nonce = os.urandom(NONCE_SIZE_BYTES)
    key = provider.get_data_key(org_id)
    return AESGCM(key).encrypt(nonce, plaintext.encode(), None), nonce


# --- round trip ---------------------------------------------------------------


def test_round_trip_recovers_the_original_plaintext():
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()

    encrypted = encrypt_secret(provider, org_id, "s3cr3t-token-value", context=CTX)

    assert encrypted.key_version == provider.current_key_version
    assert (
        decrypt_secret(
            provider, org_id, encrypted.ciphertext, encrypted.nonce, context=CTX, key_version=encrypted.key_version
        )
        == "s3cr3t-token-value"
    )


def test_round_trip_preserves_unicode_and_empty_plaintext():
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()

    for plaintext in ("", "unicode: ключ 密鑰 🔐"):
        ct, nonce, version = encrypt_secret(provider, org_id, plaintext, context=CTX)
        assert decrypt_secret(provider, org_id, ct, nonce, context=CTX, key_version=version) == plaintext


def test_decrypting_with_the_wrong_master_key_fails_closed():
    org_id = uuid.uuid4()
    right_provider = EnvKeyProvider(make_master_key())
    wrong_provider = EnvKeyProvider(make_master_key())

    ct, nonce, version = encrypt_secret(right_provider, org_id, "top-secret", context=CTX)

    # The wrong provider does not even hold that key id.
    with pytest.raises(UnknownKeyVersionError):
        decrypt_secret(wrong_provider, org_id, ct, nonce, context=CTX, key_version=version)


def test_tampered_ciphertext_fails_closed():
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()
    ct, nonce, version = encrypt_secret(provider, org_id, "top-secret", context=CTX)

    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]

    with pytest.raises(InvalidTag):
        decrypt_secret(provider, org_id, tampered, nonce, context=CTX, key_version=version)


# --- org isolation ------------------------------------------------------------


def test_data_keys_are_isolated_per_org():
    provider = EnvKeyProvider(make_master_key())
    org_a, org_b = uuid.uuid4(), uuid.uuid4()

    assert provider.get_data_key(org_a) != provider.get_data_key(org_b)


def test_a_secret_encrypted_for_one_org_cannot_be_read_as_another_orgs():
    provider = EnvKeyProvider(make_master_key())
    org_a, org_b = uuid.uuid4(), uuid.uuid4()

    ct, nonce, version = encrypt_secret(provider, org_a, "org-a-only-secret", context=CTX)

    with pytest.raises(InvalidTag):
        decrypt_secret(provider, org_b, ct, nonce, context=CTX, key_version=version)


def test_same_org_and_master_key_derive_a_stable_data_key():
    master_key = make_master_key()
    org_id = uuid.uuid4()

    assert EnvKeyProvider(master_key).get_data_key(org_id) == EnvKeyProvider(master_key).get_data_key(org_id)


# --- context binding ----------------------------------------------------------


@pytest.mark.parametrize(
    "other",
    [
        secret_context("connector_secrets", uuid.UUID(int=2), "token"),  # another row
        secret_context("connector_secrets", ROW, "client_secret"),  # another field
        secret_context("webhook_endpoints", ROW, "token"),  # another table
    ],
    ids=["other_row", "other_field", "other_table"],
)
def test_a_ciphertext_moved_to_another_row_field_or_table_fails_closed(other: bytes):
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()
    ct, nonce, version = encrypt_secret(provider, org_id, "bound", context=CTX)

    with pytest.raises(InvalidTag):
        decrypt_secret(provider, org_id, ct, nonce, context=other, key_version=version)


def test_secret_context_is_canonical_and_rejects_ambiguous_names():
    assert CTX == b"kestrel:v1:connector_secrets:00000000-0000-0000-0000-000000000001:token"
    for table, field in (("connector:secrets", "token"), ("connector_secrets", "to:ken"), ("Upper", "x"), ("", "x")):
        with pytest.raises(ValueError, match="secret context"):
            secret_context(table, ROW, field)


def test_a_bound_ciphertext_cannot_be_downgraded_to_legacy():
    """Relabelling a bound row ``key_version=0`` must not bypass the binding."""
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()
    ct, nonce, _version = encrypt_secret(provider, org_id, "bound", context=CTX)

    with pytest.raises(InvalidTag):
        decrypt_secret(provider, org_id, ct, nonce, context=CTX, key_version=LEGACY_KEY_VERSION)


# --- legacy rows --------------------------------------------------------------


def test_legacy_rows_decrypt_without_associated_data():
    provider = EnvKeyProvider(make_master_key())
    org_id = uuid.uuid4()
    ct, nonce = _legacy_ciphertext(provider, org_id, "from-0.3")

    assert decrypt_secret(provider, org_id, ct, nonce, context=CTX, key_version=LEGACY_KEY_VERSION) == "from-0.3"


def test_legacy_rows_also_decrypt_under_the_previous_key():
    old_key, new_key = make_master_key(), make_master_key()
    org_id = uuid.uuid4()
    ct, nonce = _legacy_ciphertext(EnvKeyProvider(old_key), org_id, "from-0.3")

    rotating = EnvKeyProvider(new_key, previous_key_b64=old_key)
    assert decrypt_secret(rotating, org_id, ct, nonce, context=CTX, key_version=LEGACY_KEY_VERSION) == "from-0.3"

    with pytest.raises(InvalidTag):
        decrypt_secret(EnvKeyProvider(new_key), org_id, ct, nonce, context=CTX, key_version=LEGACY_KEY_VERSION)


# --- key ids and rotation -----------------------------------------------------


def test_key_id_is_stable_distinct_and_never_the_legacy_sentinel():
    a = base64.b64decode(make_master_key())
    b = base64.b64decode(make_master_key())

    assert key_id(a) == key_id(a)
    assert key_id(a) != key_id(b)
    assert key_id(a) >= 1
    assert key_id(b) >= 1
    assert key_id(a) < 2**31  # fits a signed INTEGER column
    assert key_id(b"\x00" * 32) >= 1


def test_encrypt_always_uses_the_current_key_and_records_its_id():
    old_key, new_key = make_master_key(), make_master_key()
    provider = EnvKeyProvider(new_key, previous_key_b64=old_key)
    org_id = uuid.uuid4()

    encrypted = encrypt_secret(provider, org_id, "fresh", context=CTX)

    assert encrypted.key_version == key_id(base64.b64decode(new_key))
    assert set(provider.candidate_key_versions()) == {key_id(base64.b64decode(new_key)), key_id(base64.b64decode(old_key))}


def test_a_row_under_the_previous_key_decrypts_while_both_keys_are_held():
    old_key, new_key = make_master_key(), make_master_key()
    org_id = uuid.uuid4()
    ct, nonce, version = encrypt_secret(EnvKeyProvider(old_key), org_id, "older", context=CTX)

    rotating = EnvKeyProvider(new_key, previous_key_b64=old_key)
    assert decrypt_secret(rotating, org_id, ct, nonce, context=CTX, key_version=version) == "older"

    with pytest.raises(UnknownKeyVersionError) as excinfo:
        decrypt_secret(EnvKeyProvider(new_key), org_id, ct, nonce, context=CTX, key_version=version)
    assert "KESTREL_MASTER_KEY_PREVIOUS" in str(excinfo.value)
    assert excinfo.value.key_version == version


def test_previous_key_equal_to_current_is_rejected():
    key = make_master_key()
    with pytest.raises(ValueError, match="same key"):
        EnvKeyProvider(key, previous_key_b64=key)


def test_previous_key_is_read_from_the_environment(monkeypatch):
    old_key, new_key = make_master_key(), make_master_key()
    monkeypatch.setenv("KESTREL_MASTER_KEY", new_key)
    monkeypatch.setenv("KESTREL_MASTER_KEY_PREVIOUS", old_key)

    provider = EnvKeyProvider()

    assert len(provider.candidate_key_versions()) == 2
    assert provider.candidate_key_versions()[0] == provider.current_key_version


def test_malformed_keys_are_rejected_by_name():
    with pytest.raises(ValueError, match="KESTREL_MASTER_KEY is not valid base64"):
        EnvKeyProvider("not base64!!")
    with pytest.raises(ValueError, match="KESTREL_MASTER_KEY_PREVIOUS is not valid base64"):
        EnvKeyProvider(make_master_key(), previous_key_b64="not base64!!")


def test_short_keys_are_rejected_by_name():
    short = base64.b64encode(b"x" * 31).decode()
    with pytest.raises(ValueError, match="KESTREL_MASTER_KEY decodes to 31 bytes"):
        EnvKeyProvider(short)
    with pytest.raises(ValueError, match="KESTREL_MASTER_KEY_PREVIOUS decodes to 1 bytes"):
        EnvKeyProvider(make_master_key(), previous_key_b64="YQ==")


def test_missing_master_key_raises_a_named_error(monkeypatch):
    monkeypatch.delenv("KESTREL_MASTER_KEY", raising=False)

    with pytest.raises(MissingMasterKeyError):
        EnvKeyProvider(None)
