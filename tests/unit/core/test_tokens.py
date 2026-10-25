# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.auth.tokens`: opaque bearer tokens, stored only as a SHA-256 hash."""

from __future__ import annotations

import hashlib
import string

from kestrel.auth.tokens import generate_token, hash_token


def test_generated_tokens_are_unique():
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50


def test_generate_token_applies_the_given_prefix():
    token = generate_token(prefix="kestrel_pat_")
    assert token.startswith("kestrel_pat_")
    assert len(token) > len("kestrel_pat_")


def test_generate_token_without_a_prefix_prepends_nothing():
    """The default prefix contributes no characters at all.

    This deliberately does not assert the token lacks a leading underscore:
    `secrets.token_urlsafe` draws from the base64url alphabet, which includes
    `_`, so about 1.6% of tokens legitimately start with one. Asserting
    otherwise made this test fail roughly one run in sixty for a token that was
    perfectly valid.
    """
    unprefixed = generate_token()
    prefixed = generate_token(prefix="kestrel_pat_")

    assert len(prefixed) - len(unprefixed) == len("kestrel_pat_")
    assert set(unprefixed) <= set(string.ascii_letters + string.digits + "-_")


def test_hash_token_is_deterministic_sha256_hex():
    token = "example-raw-token-value"
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()

    assert hash_token(token) == expected
    assert hash_token(token) == hash_token(token)


def test_hash_token_differs_for_different_tokens():
    assert hash_token("token-one") != hash_token("token-two")


def test_hash_token_of_empty_string_is_well_defined():
    assert hash_token("") == hashlib.sha256(b"").hexdigest()
