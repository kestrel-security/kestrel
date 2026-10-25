# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""HMAC-SHA256 webhook signatures.

Receivers should compute HMAC-SHA256 over ``{timestamp}.{raw_body}`` using
the shared signing secret and compare to the ``v1=`` hex digest in
``X-Kestrel-Signature``. Reject deliveries whose ``X-Kestrel-Timestamp`` is
outside a reasonable skew window (recommended ±5 minutes).
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-Kestrel-Signature"
TIMESTAMP_HEADER = "X-Kestrel-Timestamp"
EVENT_HEADER = "X-Kestrel-Event"
DELIVERY_HEADER = "X-Kestrel-Delivery"

DEFAULT_TOLERANCE_SECONDS = 300


def sign_payload(*, secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, int]:
    """Returns ``(signature_header_value, timestamp)`` where the header value
    is ``v1=<hex>``."""
    ts = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(
        secret.encode("utf-8"),
        msg=f"{ts}.".encode() + body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"v1={digest}", ts


def verify_signature(
    *,
    secret: str,
    body: bytes,
    signature_header: str,
    timestamp: int,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> bool:
    """Constant-time verification of a received webhook signature."""
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance_seconds:
        return False
    expected, _ = sign_payload(secret=secret, body=body, timestamp=timestamp)
    return hmac.compare_digest(expected, signature_header)


def delivery_headers(
    *,
    signature: str,
    timestamp: int,
    event_type: str,
    delivery_id: str,
) -> dict[str, str]:
    """Outbound delivery headers for webhook receivers."""
    return {
        SIGNATURE_HEADER: signature,
        TIMESTAMP_HEADER: str(timestamp),
        EVENT_HEADER: event_type,
        DELIVERY_HEADER: delivery_id,
    }
