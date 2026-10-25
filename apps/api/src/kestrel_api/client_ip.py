# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resolve the real client IP behind trusted reverse proxies.

The API is never the first hop: under Docker Compose the Next.js server calls
it on the browser's behalf, and elsewhere a reverse proxy or ingress usually does. The TCP
peer (``request.client.host``) is therefore the proxy, so every user would
share one rate-limit bucket and one audit IP.

``KESTREL_TRUSTED_PROXIES`` lists the networks (comma-separated CIDRs or bare
addresses) allowed to tell us who the client is via ``X-Forwarded-For``. The
header is honoured only when the TCP peer is in that list, and is read right
to left, skipping further trusted hops, so a client cannot spoof its address
by sending its own ``X-Forwarded-For``: the first untrusted address is the
one the outermost trusted proxy actually saw. Unset (the default for a bare
``uvicorn`` run) means no proxy is trusted and the header is ignored.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache

from starlette.requests import Request

logger = logging.getLogger("kestrel_api.client_ip")

TRUSTED_PROXIES_ENV = "KESTREL_TRUSTED_PROXIES"

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=8)
def _parse_trusted(raw: str) -> tuple[_Network, ...]:
    networks: list[_Network] = []
    for part in raw.split(","):
        entry = part.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("ignoring invalid %s entry %r", TRUSTED_PROXIES_ENV, entry)
    return tuple(networks)


def trusted_proxy_networks() -> tuple[_Network, ...]:
    return _parse_trusted(os.environ.get(TRUSTED_PROXIES_ENV, ""))


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = value.strip().strip('"')
    # "[2001:db8::1]:443" / "203.0.113.7:51234" -- some proxies append a port.
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_trusted(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: tuple[_Network, ...]) -> bool:
    return any(addr.version == net.version and addr in net for net in networks)


def resolve_client_ip(peer: str | None, forwarded_for: str | None, networks: tuple[_Network, ...]) -> str:
    """Pure resolution step; see the module docstring for the rules."""
    if not peer:
        return "unknown"
    peer_addr = _parse_ip(peer)
    if peer_addr is None or not networks or not _is_trusted(peer_addr, networks):
        return str(peer_addr) if peer_addr is not None else peer
    if not forwarded_for:
        return str(peer_addr)

    hops = [h for h in (part.strip() for part in forwarded_for.split(",")) if h]
    client = peer_addr
    for hop in reversed(hops):
        addr = _parse_ip(hop)
        if addr is None:
            # Garbage in the chain: stop at the last address we could trust.
            break
        client = addr
        if not _is_trusted(addr, networks):
            break
    return str(client)


def client_ip(request: Request) -> str:
    """The client address for rate limiting, audit and session records."""
    peer = request.client.host if request.client else None
    return resolve_client_ip(peer, request.headers.get("x-forwarded-for"), trusted_proxy_networks())
