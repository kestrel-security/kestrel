# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Password hashing and policy via argon2-cffi (Argon2id) -- the current
OWASP-recommended default, actively maintained, and without bcrypt's
72-byte truncation footgun."""

from __future__ import annotations

import logging
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from kestrel.env import getenv_str

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

_hasher = PasswordHasher(
    time_cost=int(getenv_str("KESTREL_ARGON2_TIME_COST", "3")),
    memory_cost=int(getenv_str("KESTREL_ARGON2_MEMORY_COST", "65536")),
    parallelism=int(getenv_str("KESTREL_ARGON2_PARALLELISM", "4")),
    hash_len=32,
    salt_len=16,
)


class PasswordPolicyError(ValueError):
    pass


def validate_password_policy(raw_password: str) -> None:
    """Length-based policy per NIST 800-63B -- no composition rules."""
    if len(raw_password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(raw_password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")


def hash_password(raw_password: str) -> str:
    return _hasher.hash(raw_password)


def verify_password(raw_password: str, password_hash: str) -> bool:
    """True only when the password matches a well-formed hash.

    A corrupted or non-Argon2 ``password_hash`` fails closed: the operator
    cannot sign in, and the corruption is logged for the administrator to
    repair, rather than surfacing as a 500 on the login form.
    """
    try:
        return _hasher.verify(password_hash, raw_password)
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError) as exc:
        logger.error("password verification failed closed: stored hash is not a valid Argon2 hash (%s)", type(exc).__name__)
        return False


_dummy_hash: str | None = None


def burn_password_check(raw_password: str) -> None:
    """Spend the same Argon2 work a real verification would, then discard it.

    Login paths that fail before reaching `verify_password` (unknown email,
    inactive or locked account) call this, so their response time does not
    reveal which emails have accounts. The dummy hash is made once per
    process with the live parameters, so its cost matches real hashes.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(32))
    verify_password(raw_password, _dummy_hash)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
