// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
// Mirrors kestrel.security.ssrf.changed_endpoint_fields: config keys that
// decide where a connector sends its credentials. The API clears an
// instance's stored secrets when one of these changes, so the edit form
// warns first and lets the operator re-enter them in the same save.

const ENDPOINT_KEY_SUFFIXES = ["url", "uri", "host", "hostname", "domain", "endpoint"];

function looksLikeUrl(value: string | undefined): boolean {
  const v = (value ?? "").trim();
  return v.startsWith("http://") || v.startsWith("https://");
}

export function isEndpointConfigKey(key: string): boolean {
  const lowered = key.trim().toLowerCase().replaceAll("-", "_");
  return ENDPOINT_KEY_SUFFIXES.some((suffix) => lowered.endsWith(suffix));
}

function fingerprint(value: string | undefined): string {
  const cleaned = (value ?? "").trim().replace(/\/+$/, "");
  if (!cleaned) return "";
  if (!looksLikeUrl(cleaned)) return cleaned.toLowerCase();
  try {
    const url = new URL(cleaned);
    // Scheme and host are case-insensitive; the path is not.
    return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}${url.search}`;
  } catch {
    return cleaned;
  }
}

export function changedEndpointFields(
  before: Record<string, string | undefined>,
  after: Record<string, string | undefined>,
): string[] {
  const keys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)])).sort();
  return keys.filter((key) => {
    const a = before[key];
    const b = after[key];
    if (!(isEndpointConfigKey(key) || looksLikeUrl(a) || looksLikeUrl(b))) return false;
    return fingerprint(a) !== fingerprint(b);
  });
}
