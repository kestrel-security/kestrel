# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Envelope-style encryption for stored secrets (see
docs/adr/0004-secrets-storage-and-encryption.md).

A root key (``KESTREL_MASTER_KEY``) derives a per-org data key via HKDF, which
encrypts each secret with AES-256-GCM. Two things are bound into every
ciphertext's authentication tag:

* the **org**, through the HKDF salt, so a ciphertext cannot be read as
  another org's; and
* the **row and field it belongs to**, through GCM associated data built by
  :func:`secret_context`, so a ciphertext copied onto another row, another
  field, or another table fails to decrypt instead of silently working.

Every row also records the id of the master key that encrypted it
(``key_version``). The id is an HMAC fingerprint of the key, so an operator
who swaps keys cannot mislabel rows; ``0`` marks rows written before 0.4.0,
which carry no associated data and are re-encrypted by ``kestrel secrets
rotate``. ``KESTREL_MASTER_KEY_PREVIOUS`` keeps the retiring key readable
while that command runs.

The KeyProvider protocol is the seam a KMS/Vault-backed implementation plugs
into later without changing any call site.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import uuid
from typing import NamedTuple, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from kestrel.env import getenv

NONCE_SIZE_BYTES = 12
KEY_SIZE_BYTES = 32

MASTER_KEY_ENV = "KESTREL_MASTER_KEY"
PREVIOUS_MASTER_KEY_ENV = "KESTREL_MASTER_KEY_PREVIOUS"

#: ``key_version`` of rows written before associated data existed. They are
#: decrypted with ``associated_data=None`` and should be re-encrypted.
LEGACY_KEY_VERSION = 0

_HKDF_INFO = b"kestrel-connector-secret"
_KEY_ID_MESSAGE = b"kestrel:master-key-id"
_CONTEXT_PREFIX = b"kestrel:v1:"
_CONTEXT_TOKEN = re.compile(r"^[a-z0-9_]+$")


class MissingMasterKeyError(RuntimeError):
    pass


class UnknownKeyVersionError(RuntimeError):
    """A row was encrypted with a master key this process does not hold."""

    def __init__(self, key_version: int) -> None:
        super().__init__(
            f"a stored secret was encrypted with master key {key_version}, which is neither "
            f"{MASTER_KEY_ENV} nor {PREVIOUS_MASTER_KEY_ENV}; set {PREVIOUS_MASTER_KEY_ENV} to the "
            "retiring key and run `kestrel secrets rotate`"
        )
        self.key_version = key_version


class EncryptedSecret(NamedTuple):
    ciphertext: bytes
    nonce: bytes
    key_version: int


class KeyProvider(Protocol):
    @property
    def current_key_version(self) -> int:
        """Id of the key new ciphertexts are written with (never 0)."""
        ...

    def get_data_key(self, org_id: uuid.UUID, key_version: int | None = None) -> bytes:
        """A KEY_SIZE_BYTES-length AES-256-GCM key scoped to ``org_id``.

        ``None`` means the current key. Raises :class:`UnknownKeyVersionError`
        for a key id this provider does not hold.
        """
        ...

    def candidate_key_versions(self) -> tuple[int, ...]:
        """Key ids to try, in order, for a legacy (version 0) row."""
        ...


def key_id(master_key: bytes) -> int:
    """A stable, non-secret fingerprint of a master key, always >= 1.

    31 bits of ``HMAC-SHA256(master_key, "kestrel:master-key-id")``, so it
    fits a signed INTEGER column and reveals nothing useful about the key.
    Two keys could in principle collide; the chance is one in two billion.
    """
    digest = hmac.new(master_key, _KEY_ID_MESSAGE, hashlib.sha256).digest()
    value = int.from_bytes(digest[:4], "big") >> 1
    return max(1, value)


def secret_context(table: str, row_id: uuid.UUID, field: str) -> bytes:
    """Associated data binding a ciphertext to one (table, row, field).

    ``b"kestrel:v1:<table>:<row uuid>:<field>"``. ``table`` and ``field`` are
    restricted to ``[a-z0-9_]`` so the encoding has no ambiguity.
    """
    for name, value in (("table", table), ("field", field)):
        if not _CONTEXT_TOKEN.match(value):
            raise ValueError(f"secret context {name} must match [a-z0-9_]+, got {value!r}")
    return _CONTEXT_PREFIX + f"{table}:{row_id}:{field}".encode("ascii")


# HKDF stretches whatever it is given; it cannot add entropy a short key lacks.
MIN_MASTER_KEY_BYTES = 32


def _decode_key(raw: str, *, env_name: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{env_name} is not valid base64") from exc
    if len(key) < MIN_MASTER_KEY_BYTES:
        raise ValueError(
            f"{env_name} decodes to {len(key)} bytes; it must be at least {MIN_MASTER_KEY_BYTES} "
            "random bytes (generate one with: openssl rand -base64 32)"
        )
    return key


class EnvKeyProvider:
    """Derives per-org keys from ``KESTREL_MASTER_KEY`` (and, during a
    rotation, ``KESTREL_MASTER_KEY_PREVIOUS``) via HKDF with the org id as
    salt. Not a substitute for a KMS; see ADR-0004.
    """

    def __init__(self, master_key_b64: str | None = None, previous_key_b64: str | None = None) -> None:
        raw = master_key_b64 or getenv(MASTER_KEY_ENV)
        if not raw:
            raise MissingMasterKeyError(
                f"{MASTER_KEY_ENV} is not set -- run `kestrel init` to generate one, or set it in .env"
            )
        self._master_key = _decode_key(raw, env_name=MASTER_KEY_ENV)
        self._current_version = key_id(self._master_key)
        self._keys: dict[int, bytes] = {self._current_version: self._master_key}

        raw_previous = previous_key_b64 if previous_key_b64 is not None else getenv(PREVIOUS_MASTER_KEY_ENV)
        if raw_previous:
            previous = _decode_key(raw_previous, env_name=PREVIOUS_MASTER_KEY_ENV)
            if hmac.compare_digest(previous, self._master_key):
                raise ValueError(f"{PREVIOUS_MASTER_KEY_ENV} is the same key as {MASTER_KEY_ENV}; unset it")
            self._keys[key_id(previous)] = previous

    @property
    def current_key_version(self) -> int:
        return self._current_version

    def candidate_key_versions(self) -> tuple[int, ...]:
        return tuple(self._keys)

    def get_data_key(self, org_id: uuid.UUID, key_version: int | None = None) -> bytes:
        version = self._current_version if key_version is None else key_version
        master = self._keys.get(version)
        if master is None:
            raise UnknownKeyVersionError(version)
        hkdf = HKDF(algorithm=SHA256(), length=KEY_SIZE_BYTES, salt=org_id.bytes, info=_HKDF_INFO)
        return hkdf.derive(master)


def encrypt_secret(key_provider: KeyProvider, org_id: uuid.UUID, plaintext: str, *, context: bytes) -> EncryptedSecret:
    """Encrypt ``plaintext`` under the current key, bound to ``context``.

    ``context`` comes from :func:`secret_context` and must be the same bytes
    the caller will pass to :func:`decrypt_secret`.
    """
    key = key_provider.get_data_key(org_id)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), associated_data=context)
    return EncryptedSecret(ciphertext, nonce, key_provider.current_key_version)


def decrypt_secret(
    key_provider: KeyProvider,
    org_id: uuid.UUID,
    ciphertext: bytes,
    nonce: bytes,
    *,
    context: bytes,
    key_version: int,
) -> str:
    """Decrypt a stored secret.

    Raises ``cryptography.exceptions.InvalidTag`` if the ciphertext was
    tampered with, moved to another row/field/table, or encrypted under a
    different org; :class:`UnknownKeyVersionError` if ``key_version`` names
    a master key this process does not hold.

    Rows with ``key_version == LEGACY_KEY_VERSION`` predate associated data
    and are tried without it, under the current key and then the previous
    one. A context-bound ciphertext never verifies that way, so relabelling a
    bound row as legacy does not bypass the binding.
    """
    if key_version == LEGACY_KEY_VERSION:
        last_error: InvalidTag | None = None
        for candidate in key_provider.candidate_key_versions():
            key = key_provider.get_data_key(org_id, candidate)
            try:
                return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None).decode("utf-8")
            except InvalidTag as exc:
                last_error = exc
        raise last_error or InvalidTag()
    key = key_provider.get_data_key(org_id, key_version)
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=context).decode("utf-8")
