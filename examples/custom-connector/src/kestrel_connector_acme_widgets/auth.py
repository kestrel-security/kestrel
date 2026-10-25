# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
from kestrel.connectors.sdk.transport import LiveHTTPTransport


def build_live_transport(config: dict, secrets: dict[str, str]) -> LiveHTTPTransport:
    return LiveHTTPTransport(
        base_url=config["base_url"],
        headers={"Authorization": f"Bearer {secrets['api_key']}"},
    )
