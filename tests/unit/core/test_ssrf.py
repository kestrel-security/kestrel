# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.security.ssrf.validate_connector_url`: default-deny SSRF guard for
connector-supplied URLs.

Every case here uses an IP literal as the host, never a hostname -- the
function short-circuits on `ipaddress.ip_address(hostname)` before ever
reaching `socket.getaddrinfo`, so these tests never touch DNS and stay
network-free by construction (see the module docstring's "resolves the
hostname once" and the literal-vs-name branch in `validate_connector_url`).
"""

from __future__ import annotations

import pytest
from kestrel.security.ssrf import (
    UnsafeConnectorURLError,
    allowlisted_connector_hosts,
    changed_endpoint_fields,
    validate_connector_config_urls,
    validate_connector_url,
)


def test_a_public_ip_literal_is_accepted():
    validate_connector_url("https://93.184.216.34/status")  # must not raise


def test_loopback_ip_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://127.0.0.1/")


def test_private_rfc1918_ip_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://10.0.0.5:9200/")


def test_cloud_metadata_link_local_ip_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://169.254.169.254/latest/meta-data/")


def test_ipv6_loopback_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://[::1]/")


def test_ipv6_unique_local_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://[fd00::1]/")


def test_multicast_ip_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://224.0.0.1/")


def test_unsupported_scheme_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("ftp://93.184.216.34/")


def test_missing_host_is_rejected():
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http:///no-host")


def test_field_name_is_included_in_the_error_message():
    with pytest.raises(UnsafeConnectorURLError, match="webhook_url"):
        validate_connector_url("http://127.0.0.1/", field="webhook_url")


def test_allowlisting_a_private_ip_literal_permits_it(monkeypatch):
    # Documented use case: a lab app on loopback/private, allowlisted by an
    # operator who accepts the risk (module docstring: "an internal app on
    # loopback"). The host string in the URL is itself the allowlist entry.
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "10.0.0.5")
    validate_connector_url("http://10.0.0.5/", field="base_url")  # must not raise


def test_a_private_ip_not_on_the_allowlist_is_still_rejected(monkeypatch):
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "10.0.0.9")
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://10.0.0.5/", field="base_url")


def test_link_local_is_rejected_even_when_allowlisted(monkeypatch):
    # link-local / metadata addresses are never allowed, allowlist or not.
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "169.254.169.254")
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://169.254.169.254/", field="base_url")


def test_allowlist_parses_comma_separated_hostnames_case_insensitively(monkeypatch):
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", " Harbor.Lab , other-host ")
    assert allowlisted_connector_hosts() == {"harbor.lab", "other-host"}


def test_allowlist_is_empty_when_unset(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    assert allowlisted_connector_hosts() == set()


def test_validate_connector_config_urls_walks_only_url_shaped_string_values():
    config = {
        "base_url": "http://93.184.216.34/",
        "org_login": "not-a-url",
        "retries": 3,
        "webhook_url": "http://10.0.0.5/hook",
    }

    with pytest.raises(UnsafeConnectorURLError, match="webhook_url"):
        validate_connector_config_urls(config)


def test_validate_connector_config_urls_accepts_a_config_with_no_unsafe_urls():
    validate_connector_config_urls(
        {"base_url": "https://93.184.216.34/", "org_login": "some-org", "retries": 3}
    )  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "http://100.100.100.200/latest/meta-data",  # Alibaba Cloud metadata (CGNAT range)
        "http://100.64.0.1/",  # shared address space / Tailscale
        "http://198.18.0.1/",  # benchmarking
        "http://192.0.2.10/",  # documentation (TEST-NET-1)
        "http://[2001:db8::1]/",  # documentation
        "http://240.0.0.1/",  # reserved
        "http://168.63.129.16/",  # Azure WireServer: a public address, still metadata
    ],
)
def test_non_global_and_metadata_addresses_are_rejected(url):
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url(url)


def test_metadata_addresses_are_rejected_even_when_allowlisted(monkeypatch):
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "100.100.100.200")
    with pytest.raises(UnsafeConnectorURLError):
        validate_connector_url("http://100.100.100.200/")


def test_allowlisted_cgnat_lab_host_is_still_permitted(monkeypatch):
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "100.64.0.7")
    validate_connector_url("http://100.64.0.7/", require_https=True)  # must not raise


def test_require_https_refuses_plain_http_for_public_hosts(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    with pytest.raises(UnsafeConnectorURLError, match="https"):
        validate_connector_url("http://93.184.216.34/", require_https=True)
    validate_connector_url("https://93.184.216.34/", require_https=True)  # must not raise


def test_config_walk_passes_require_https_through(monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    with pytest.raises(UnsafeConnectorURLError, match="base_url"):
        validate_connector_config_urls({"base_url": "http://93.184.216.34/"}, require_https=True)


def test_changed_endpoint_fields_flags_url_and_host_keys_only():
    old = {"org_url": "https://acme.okta.com", "org_login": "acme", "domain": "acme.example", "target": "https://a/"}
    new = {"org_url": "https://evil.example", "org_login": "other", "domain": "acme.example", "target": "https://b/"}
    assert changed_endpoint_fields(old, new) == ["org_url", "target"]


def test_changed_endpoint_fields_ignores_cosmetic_differences():
    assert changed_endpoint_fields({"org_url": "https://acme.okta.com"}, {"org_url": " https://ACME.okta.com/ "}) == []


def test_changed_endpoint_fields_counts_added_and_removed_keys():
    assert changed_endpoint_fields({}, {"base_url": "https://x.example"}) == ["base_url"]
    assert changed_endpoint_fields({"api_host": "x.example"}, {}) == ["api_host"]
