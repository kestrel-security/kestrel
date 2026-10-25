# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.auth.passwords`: policy validation and Argon2id hash/verify.

Hashing itself is exercised at test-cost Argon2 parameters (set by the root
conftest before this module -- or `kestrel.auth.passwords` -- is ever
imported), so these tests stay fast without weakening what they prove: the
hash is still real Argon2id and still round-trips.
"""

from __future__ import annotations

import pytest
from kestrel.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    needs_rehash,
    validate_password_policy,
    verify_password,
)


def test_password_at_the_minimum_length_is_accepted():
    validate_password_policy("x" * MIN_PASSWORD_LENGTH)  # must not raise


def test_password_at_the_maximum_length_is_accepted():
    validate_password_policy("x" * MAX_PASSWORD_LENGTH)  # must not raise


def test_password_one_below_minimum_is_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password_policy("x" * (MIN_PASSWORD_LENGTH - 1))


def test_password_one_above_maximum_is_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password_policy("x" * (MAX_PASSWORD_LENGTH + 1))


def test_empty_password_is_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password_policy("")


def test_hash_and_verify_round_trip():
    digest = hash_password("a reasonably long passphrase")
    assert digest.startswith("$argon2id$")
    assert verify_password("a reasonably long passphrase", digest) is True


def test_verify_rejects_the_wrong_password():
    digest = hash_password("a reasonably long passphrase")
    assert verify_password("a different passphrase entirely", digest) is False


def test_verify_fails_closed_for_a_hash_in_the_wrong_format(caplog):
    # A corrupted `password_hash` must read as "wrong password", never as a
    # 500 on the login form; the corruption is logged for repair.
    with caplog.at_level("ERROR"):
        assert verify_password("whatever", "not-an-argon2-hash") is False
    assert "not a valid Argon2 hash" in caplog.text


def test_hash_round_trips_unicode_passwords():
    digest = hash_password("pässwörd-密碼-🔑-correct-horse")
    assert verify_password("pässwörd-密碼-🔑-correct-horse", digest) is True
    assert verify_password("pässwörd-密碼-🔑-wrong-horse", digest) is False


def test_two_hashes_of_the_same_password_are_not_identical():
    # Argon2id salts per call -- equal hashes would mean a fixed/reused salt.
    first = hash_password("same-password-both-times")
    second = hash_password("same-password-both-times")
    assert first != second
    assert verify_password("same-password-both-times", first)
    assert verify_password("same-password-both-times", second)


def test_a_freshly_hashed_password_does_not_need_rehash():
    assert needs_rehash(hash_password("fresh-password-value")) is False


def test_burn_password_check_runs_a_real_argon2_verification(monkeypatch):
    # The unknown-email / inactive / locked login paths call this so they cost
    # the same Argon2 work as a wrong password (no account enumeration by
    # timing). It must actually verify, against a hash made with the live
    # parameters, and never accept anything.
    from kestrel.auth import passwords

    calls: list[str] = []
    real_verify = passwords.verify_password

    def spy(raw: str, hash_: str) -> bool:
        calls.append(hash_)
        result = real_verify(raw, hash_)
        assert result is False
        return result

    monkeypatch.setattr(passwords, "verify_password", spy)
    passwords.burn_password_check("any-password-at-all")
    passwords.burn_password_check("another-password")

    assert len(calls) == 2
    assert calls[0] == calls[1]  # one dummy hash per process
    assert calls[0].startswith("$argon2id$")
