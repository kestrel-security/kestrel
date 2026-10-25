# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- the TOTP primitives in kestrel.auth.mfa, pinned to RFC 6238."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from kestrel.auth import mfa

# RFC 6238 Appendix B: SHA-1 seed "12345678901234567890", 8-digit codes.
_RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
_RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("unix_time", "expected"), _RFC_VECTORS)
def test_hotp_matches_the_rfc_6238_vectors(unix_time: int, expected: str) -> None:
    step = unix_time // mfa.STEP_SECONDS
    assert mfa.hotp(mfa._key(_RFC_SECRET), step, digits=8) == expected


@pytest.mark.parametrize(("unix_time", "expected"), _RFC_VECTORS)
def test_six_digit_codes_are_the_low_digits_of_the_rfc_values(unix_time: int, expected: str) -> None:
    assert mfa.totp(_RFC_SECRET, datetime.fromtimestamp(unix_time, UTC)) == expected[-6:]


def _now() -> datetime:
    return datetime(2026, 10, 7, 12, 0, 15, tzinfo=UTC)


def test_a_code_from_one_step_either_side_is_accepted_and_two_steps_is_not() -> None:
    secret = mfa.generate_secret()
    now = _now()
    for offset, accepted in ((-1, True), (0, True), (1, True), (-2, False), (2, False)):
        code = mfa.totp(secret, now + timedelta(seconds=offset * mfa.STEP_SECONDS))
        assert (mfa.verify_totp(secret, code, now, None) is not None) is accepted, offset


def test_a_code_cannot_be_replayed() -> None:
    secret = mfa.generate_secret()
    now = _now()
    code = mfa.totp(secret, now)
    step = mfa.verify_totp(secret, code, now, None)
    assert step is not None
    assert mfa.verify_totp(secret, code, now, last_used_step=step) is None


def test_codes_are_compared_without_spaces() -> None:
    secret = mfa.generate_secret()
    code = mfa.totp(secret, _now())
    assert mfa.verify_totp(secret, f" {code[:3]} {code[3:]} ", _now(), None) is not None
    assert mfa.verify_totp(secret, "12345", _now(), None) is None
    assert mfa.verify_totp(secret, "abcdef", _now(), None) is None


def test_the_otpauth_uri_is_what_authenticator_apps_read() -> None:
    uri = urlparse(mfa.otpauth_uri("JBSWY3DPEHPK3PXP", "ada@example.com"))
    assert (uri.scheme, uri.netloc, uri.path) == ("otpauth", "totp", "/Kestrel:ada@example.com")
    params = parse_qs(uri.query)
    assert params["secret"] == ["JBSWY3DPEHPK3PXP"]
    assert params["issuer"] == ["Kestrel"]
    assert params["digits"] == ["6"]
    assert params["period"] == ["30"]


def test_generated_secrets_are_160_bit_base32() -> None:
    secret = mfa.generate_secret()
    assert len(mfa._key(secret)) == 20
    assert secret != mfa.generate_secret()


def test_recovery_codes_are_distinct_and_unambiguous() -> None:
    codes = mfa.generate_recovery_codes()
    assert len(codes) == mfa.RECOVERY_CODE_COUNT == len(set(codes))
    for code in codes:
        assert len(code) == 9
        assert code[4] == "-"
        assert not set(code) & set("0o1liI")
    assert mfa.normalize_code(" ABCD-efgh ") == "abcdefgh"
