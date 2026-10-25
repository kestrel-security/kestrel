# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared SSRF guard for every operator-supplied outbound URL: connector
config (base_url and similar), webhook endpoints, the Jira base URL, and the
AI provider base URL.

Connector-instance config is operator-supplied and, for custom/community
connectors, can end up driving a real outbound HTTP request from the API or
worker process (`LiveHTTPTransport`). Without validation, a config value
like `http://169.254.169.254/latest/meta-data/` or `http://10.0.0.5:9200/`
would make Kestrel's own backend issue requests to internal infrastructure or
cloud metadata endpoints on the operator's behalf -- see
docs/threat-model.md.

This is a default-deny guard, not a network-level control: it resolves the
hostname once and rejects every address that is not globally routable
(``not ip.is_global``: private, loopback, link-local, CGNAT 100.64.0.0/10,
benchmarking, documentation ranges, ...) plus reserved and multicast ones.

Validation and connection are separate steps: the resolved address is not
pinned for the request that follows, so DNS rebinding (a name that resolves
to a public address here and a private one a moment later) remains a
residual risk. Callers narrow the window by validating immediately before
each request -- `LiveHTTPTransport` at construction, webhook delivery and the
Jira provider before every send -- and docs/threat-model.md records the gap.

Local/lab apps (e.g. an internal app on loopback) may be allowlisted via
`KESTREL_CONNECTOR_URL_ALLOWLIST` (comma-separated hostnames). The allowlist
is empty by default. Link-local / cloud-metadata addresses are still
rejected even if listed.

Callers that send a credential with the request pass ``require_https=True``:
plain ``http://`` is then refused unless the host is on the allowlist (the
local-lab case), so a token never crosses the network in cleartext.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWLIST_ENV = "KESTREL_CONNECTOR_URL_ALLOWLIST"


class UnsafeConnectorURLError(ValueError):
    """A connector-configured URL is missing, malformed, or resolves to a
    disallowed (private/loopback/link-local/reserved/multicast) address."""


# Cloud instance-metadata / host-agent addresses that are not link-local, so
# `is_link_local` alone would let an allowlisted name resolve to them:
# Alibaba Cloud (100.100.100.200), AWS IMDS over IPv6 (fd00:ec2::254), Azure
# WireServer (168.63.129.16, a *public* address), Oracle Cloud (192.0.0.192).
_METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("100.100.100.200", "fd00:ec2::254", "168.63.129.16", "192.0.0.192")
)


def _is_link_local_or_unspecified(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Never allowed, allowlisted or not."""
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip in _METADATA_IPS


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Anything that is not a globally routable unicast address.

    ``is_global`` is False for RFC 1918, loopback, link-local (cloud
    metadata), CGNAT 100.64.0.0/10, benchmarking, documentation and other
    special-purpose ranges. Reserved and multicast are checked explicitly
    because ``is_global`` is True for some of them (e.g. NAT64 64:ff9b::/96,
    global-scope multicast).
    """
    return not ip.is_global or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def allowlisted_connector_hosts() -> set[str]:
    raw = os.environ.get(_ALLOWLIST_ENV, "")
    return {part.strip().casefold() for part in raw.split(",") if part.strip()}


def validate_connector_url(url: str, *, field: str = "url", require_https: bool = False) -> None:
    """Raises UnsafeConnectorURLError unless `url` is an absolute http(s) URL
    whose host resolves only to public addresses, or whose hostname is on
    `KESTREL_CONNECTOR_URL_ALLOWLIST` (still never link-local / metadata).

    ``require_https`` additionally refuses ``http://`` for hosts that are not
    allowlisted; pass it wherever the request will carry a credential."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeConnectorURLError(f"{field}: unsupported scheme {parsed.scheme!r} (must be http or https)")
    if not parsed.hostname:
        raise UnsafeConnectorURLError(f"{field}: URL is missing a host")

    hostname = parsed.hostname
    allowlisted = hostname.casefold() in allowlisted_connector_hosts()
    if require_https and parsed.scheme != "https" and not allowlisted:
        raise UnsafeConnectorURLError(f"{field}: must use https (plain http is only allowed for hosts on {_ALLOWLIST_ENV})")

    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise UnsafeConnectorURLError(f"{field}: could not resolve host {hostname!r}: {exc}") from exc
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]

    if not addresses:
        raise UnsafeConnectorURLError(f"{field}: host {hostname!r} did not resolve to any address")

    for addr in addresses:
        if _is_link_local_or_unspecified(addr):
            raise UnsafeConnectorURLError(
                f"{field}: {hostname!r} resolves to a link-local, reserved, multicast, or "
                f"unspecified address ({addr}), which connector configuration is not allowed to target"
            )
        if allowlisted:
            continue
        if _is_unsafe_ip(addr):
            raise UnsafeConnectorURLError(
                f"{field}: {hostname!r} resolves to a non-public (private, loopback, shared/CGNAT, "
                f"reserved, or multicast) address ({addr}), which connector configuration is not allowed to target"
            )


def validate_smtp_host(host: str, *, field: str = "host") -> None:
    """Raises UnsafeConnectorURLError if an admin-configured mail server host
    is malformed or resolves to a link-local, cloud-metadata, reserved,
    multicast, or unspecified address.

    Unlike connector URLs, private and loopback addresses are allowed: an
    internal relay (or a sidecar on localhost) is the normal way to send
    mail, and the setting is admin-only and audited. Metadata endpoints stay
    off-limits whatever the network."""
    hostname = host.strip()
    if not hostname or (any(c in hostname for c in "/:@ ") and not _is_ipv6_literal(hostname)):
        raise UnsafeConnectorURLError(f"{field}: expected a hostname or IP address, got {host!r}")

    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise UnsafeConnectorURLError(f"{field}: could not resolve host {hostname!r}: {exc}") from exc
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]

    if not addresses:
        raise UnsafeConnectorURLError(f"{field}: host {hostname!r} did not resolve to any address")
    for addr in addresses:
        # ::1 sits in a reserved IPv6 range, so loopback is let through by name.
        if not addr.is_loopback and _is_link_local_or_unspecified(addr):
            raise UnsafeConnectorURLError(
                f"{field}: {hostname!r} resolves to a link-local, reserved, multicast, or "
                f"unspecified address ({addr}), which a mail server is not allowed to use"
            )


def _is_ipv6_literal(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def validate_connector_config_urls(config: dict, *, require_https: bool = False) -> None:
    """Walks a connector-instance config dict and validates every top-level
    string value that looks like an absolute http(s) URL. Generic by design:
    connector config shapes vary by manifest (base_url, webhook_url, ...)
    and manifests don't currently declare which fields are URL-typed.

    Pass ``require_https=True`` for live-mode instances: their URLs receive
    the instance's stored credentials."""
    for key, value in config.items():
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            validate_connector_url(value, field=key, require_https=require_https)


_ENDPOINT_KEY_SUFFIXES = ("url", "uri", "host", "hostname", "domain", "endpoint")


def is_endpoint_config_key(key: str) -> bool:
    """True for config keys that name where requests (and credentials) go.

    Manifests declare config fields by name only, so this is name-based:
    ``org_url``, ``base_url``, ``token_uri``, ``api_host``, ``domain``, ...
    """
    lowered = key.strip().lower().replace("-", "_")
    return lowered.endswith(_ENDPOINT_KEY_SUFFIXES)


def changed_endpoint_fields(old: dict | None, new: dict | None) -> list[str]:
    """Config keys whose value decides the request target and that differ
    between ``old`` and ``new``.

    A key counts when its name looks like an endpoint (see
    `is_endpoint_config_key`) or either value is an absolute http(s) URL.
    Comparison ignores surrounding whitespace, a trailing slash and host
    case, so re-saving an unchanged form is not a change.
    """
    old = old or {}
    new = new or {}
    changed: list[str] = []
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key), new.get(key)
        looks_like_url = any(isinstance(v, str) and v.strip().startswith(("http://", "https://")) for v in (before, after))
        if not (is_endpoint_config_key(str(key)) or looks_like_url):
            continue
        if _endpoint_fingerprint(before) != _endpoint_fingerprint(after):
            changed.append(str(key))
    return changed


def _endpoint_fingerprint(value: object) -> object:
    if not isinstance(value, str):
        return value
    cleaned = value.strip().rstrip("/")
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
    return cleaned.lower()
