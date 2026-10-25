# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Maps RawObjects into Kestrel NormalizedObjects. Pure function-ish: no
I/O, fully unit-testable without network or DB access."""

from __future__ import annotations

from kestrel.connectors.sdk.base import NormalizedObject, RawObject


class AcmeWidgetsNormalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        if object_type != "user":
            raise ValueError(f"Unsupported object_type '{object_type}'")
        payload = raw.payload
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes={
                    "identity_type": "user",
                    "display_name": payload.get("name"),
                    "email": payload.get("email"),
                    "is_disabled": False,
                    "is_external": False,
                    "mfa_enabled": None,
                },
                raw_source=payload,
            )
        ]
