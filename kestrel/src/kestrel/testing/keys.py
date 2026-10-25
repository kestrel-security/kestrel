# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Key material helpers for tests."""

from __future__ import annotations

import base64
import os

from kestrel.secrets.crypto import KEY_SIZE_BYTES

MASTER_KEY_ENV_VAR = "KESTREL_MASTER_KEY"
MASTER_KEY_PREVIOUS_ENV_VAR = "KESTREL_MASTER_KEY_PREVIOUS"


def make_master_key(*, deterministic: bool = False) -> str:
    """A valid ``KESTREL_MASTER_KEY`` value: base64 of 32 random bytes.

    ``EnvKeyProvider`` base64-decodes this and feeds it to HKDF, so anything
    that is not exactly ``KEY_SIZE_BYTES`` of decoded key material fails
    late and confusingly. Pass ``deterministic=True`` for a fixed key when a
    test needs ciphertext to be reproducible across runs -- never for anything
    that stores real secrets.
    """
    raw = bytes(range(KEY_SIZE_BYTES)) if deterministic else os.urandom(KEY_SIZE_BYTES)
    return base64.b64encode(raw).decode("ascii")
