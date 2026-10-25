# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""TOTP multi-factor authentication for operators (RFC 6238).

Time-based one-time passwords as every authenticator app generates them:
HMAC-SHA1, 6 digits, a 30-second step, accepting one step either side for
clock drift. Implemented with the standard library rather than a dependency;
the RFC 6238 test vectors pin it (tests/unit/auth/test_mfa.py).

The secret is encrypted with the org key (kestrel.secrets.crypto). It is
stored when enrolment starts but only counts once the operator proves they
can generate a code (``mfa_enabled_at``). The last accepted time step is
kept so a code cannot be replayed within its window.

Recovery codes are single-use, shown once, and stored as SHA-256 hashes like
session tokens. A wrong code counts toward the same lockout as a wrong
password, so the second factor cannot be brute-forced around it.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import struct
import uuid
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.auth.tokens import hash_token
from kestrel.db.models.operator import Operator, OperatorMfaRecoveryCode
from kestrel.secrets.crypto import EnvKeyProvider, KeyProvider, decrypt_secret, encrypt_secret, secret_context

ISSUER = "Kestrel"
DIGITS = 6
STEP_SECONDS = 30
#: Steps accepted either side of now, for clock drift between phone and server.
WINDOW = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


class MfaError(ValueError):
    """An MFA operation the caller asked for that cannot be done in the current state."""


# --- TOTP -------------------------------------------------------------------


def generate_secret() -> str:
    """A fresh 160-bit secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def otpauth_uri(secret: str, account: str, issuer: str = ISSUER) -> str:
    """The `otpauth://` URI an authenticator app reads from a QR code."""
    label = quote(f"{issuer}:{account}", safe=":@")
    params = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{params}"


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest: str = "sha1") -> str:
    """RFC 4226 HOTP value for ``counter``."""
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def time_step(now: datetime) -> int:
    return int(now.timestamp()) // STEP_SECONDS


def totp(secret: str, now: datetime) -> str:
    return hotp(_key(secret), time_step(now))


def verify_totp(secret: str, code: str, now: datetime, last_used_step: int | None) -> int | None:
    """The time step ``code`` matches within the window, or None.

    A step at or before ``last_used_step`` never matches, so an observed
    code cannot be replayed.
    """
    code = normalize_code(code)
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = _key(secret)
    current = time_step(now)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def code_already_used(operator: Operator, code: str, now: datetime, key_provider: KeyProvider | None = None) -> bool:
    """True when ``code`` is valid but was the last one accepted, i.e. a replay
    within its window. Lets the UI say "wait for the next code" instead of
    "invalid"; it is still refused."""
    if not is_enrolled(operator) or operator.mfa_last_used_step is None:
        return False
    code = normalize_code(code)
    secret = _secret(operator, key_provider or EnvKeyProvider())
    return hmac.compare_digest(hotp(_key(secret), operator.mfa_last_used_step), code)


def normalize_code(code: str) -> str:
    """Codes are typed with spaces, dashes, and either case; compare without them."""
    return "".join(ch for ch in code.strip().lower() if ch not in " -")


# --- Recovery codes ---------------------------------------------------------


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Human-friendly single-use codes, ``xxxx-xxxx``, with no look-alike characters."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def _recovery_hash(code: str) -> str:
    return hash_token(normalize_code(code))


def replace_recovery_codes(db: Session, operator: Operator, now: datetime) -> list[str]:
    """Discard the operator's recovery codes and issue a fresh set (plaintext returned once)."""
    for row in db.scalars(select(OperatorMfaRecoveryCode).where(OperatorMfaRecoveryCode.operator_id == operator.id)):
        db.delete(row)
    codes = generate_recovery_codes()
    db.add_all(
        OperatorMfaRecoveryCode(id=uuid.uuid4(), operator_id=operator.id, code_hash=_recovery_hash(c), created_at=now)
        for c in codes
    )
    db.flush()
    return codes


def remaining_recovery_codes(db: Session, operator: Operator) -> int:
    return len(
        db.scalars(
            select(OperatorMfaRecoveryCode.id).where(
                OperatorMfaRecoveryCode.operator_id == operator.id, OperatorMfaRecoveryCode.used_at.is_(None)
            )
        ).all()
    )


def _consume_recovery_code(db: Session, operator: Operator, code: str, now: datetime) -> bool:
    row = db.scalars(
        select(OperatorMfaRecoveryCode)
        .where(
            OperatorMfaRecoveryCode.operator_id == operator.id,
            OperatorMfaRecoveryCode.code_hash == _recovery_hash(code),
            OperatorMfaRecoveryCode.used_at.is_(None),
        )
        .with_for_update()
    ).one_or_none()
    if row is None:
        return False
    row.used_at = now
    return True


# --- Operator state -----------------------------------------------------------


def is_enrolled(operator: Operator) -> bool:
    return operator.mfa_enabled_at is not None and operator.mfa_secret_ciphertext is not None


def mfa_secret_context(operator_id: uuid.UUID) -> bytes:
    """Associated data binding a TOTP secret to its operator row."""
    return secret_context(Operator.__tablename__, operator_id, "mfa_secret")


def _secret(operator: Operator, key_provider: KeyProvider) -> str:
    if (
        operator.mfa_secret_ciphertext is None
        or operator.mfa_secret_nonce is None
        or operator.mfa_secret_key_version is None
    ):
        raise MfaError("no authenticator is set up")
    return decrypt_secret(
        key_provider,
        operator.org_id,
        operator.mfa_secret_ciphertext,
        operator.mfa_secret_nonce,
        context=mfa_secret_context(operator.id),
        key_version=operator.mfa_secret_key_version,
    )


def start_enrolment(operator: Operator, key_provider: KeyProvider | None = None) -> tuple[str, str]:
    """Store a new pending secret and return ``(secret, otpauth_uri)``.

    Starting again replaces a pending secret. An operator already enrolled
    must turn MFA off first, so a stolen session cannot silently swap the
    authenticator.
    """
    if is_enrolled(operator):
        raise MfaError("two-factor authentication is already on; turn it off before setting up a new authenticator")
    secret = generate_secret()
    encrypted = encrypt_secret(
        key_provider or EnvKeyProvider(), operator.org_id, secret, context=mfa_secret_context(operator.id)
    )
    operator.mfa_secret_ciphertext = encrypted.ciphertext
    operator.mfa_secret_nonce = encrypted.nonce
    operator.mfa_secret_key_version = encrypted.key_version
    operator.mfa_enabled_at = None
    operator.mfa_last_used_step = None
    return secret, otpauth_uri(secret, operator.email)


def activate(
    db: Session, operator: Operator, code: str, *, now: datetime | None = None, key_provider: KeyProvider | None = None
) -> list[str]:
    """Confirm the pending authenticator with a first code; returns the recovery codes."""
    now = now or datetime.now(UTC)
    if is_enrolled(operator):
        raise MfaError("two-factor authentication is already on")
    step = verify_totp(_secret(operator, key_provider or EnvKeyProvider()), code, now, operator.mfa_last_used_step)
    if step is None:
        raise MfaError("that code is not valid; check the time on your device and try the current code")
    operator.mfa_enabled_at = now
    operator.mfa_last_used_step = step
    return replace_recovery_codes(db, operator, now)


def lock_operator(db: Session, operator: Operator) -> None:
    """Reload MFA state under a row lock held until the caller commits.

    All second-factor consumption uses this lock before recovery-code or
    challenge locks, so overlapping requests cannot accept stale TOTP state.
    """
    db.refresh(operator, with_for_update=True)


def verify_second_factor(
    db: Session,
    operator: Operator,
    code: str,
    *,
    now: datetime | None = None,
    key_provider: KeyProvider | None = None,
) -> str | None:
    """Check a TOTP or recovery code for an enrolled operator.

    Returns ``"totp"`` or ``"recovery_code"`` on success and None otherwise.
    A wrong code counts toward the account lockout like a wrong password.
    """
    from kestrel.auth.service import record_failed_attempt

    lock_operator(db, operator)
    now = now or datetime.now(UTC)
    if not is_enrolled(operator):
        return None
    if operator.locked_until is not None and operator.locked_until > now:
        return None
    step = verify_totp(_secret(operator, key_provider or EnvKeyProvider()), code, now, operator.mfa_last_used_step)
    if step is not None:
        operator.mfa_last_used_step = step
        return "totp"
    if _consume_recovery_code(db, operator, code, now):
        return "recovery_code"
    record_failed_attempt(db, operator, now)
    return None


def disable(db: Session, operator: Operator) -> None:
    """Remove the operator's authenticator and recovery codes."""
    operator.mfa_secret_ciphertext = None
    operator.mfa_secret_nonce = None
    operator.mfa_enabled_at = None
    operator.mfa_last_used_step = None
    for row in db.scalars(select(OperatorMfaRecoveryCode).where(OperatorMfaRecoveryCode.operator_id == operator.id)):
        db.delete(row)
    db.flush()


def reset(db: Session, operator: Operator) -> int:
    """Admin or CLI reset for a lost device: removes MFA and ends every session.

    Returns the number of sessions revoked. If the org requires MFA, the
    operator is asked to enrol again at their next sign-in.
    """
    from kestrel.auth.service import revoke_operator_sessions

    disable(db, operator)
    return revoke_operator_sessions(db, operator.id)
