// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Default page size for identities / findings list UI (matches API default). */
export const LIST_PAGE_SIZE = 50;

/** Build a same-page query href, toggling or setting one key. */
export function filterHref(
  basePath: string,
  current: URLSearchParams,
  key: string,
  value: string,
  { toggle = true }: { toggle?: boolean } = {},
): string {
  const next = new URLSearchParams(current);
  if (toggle && next.get(key) === value) next.delete(key);
  else next.set(key, value);
  const qs = next.toString();
  return qs ? `${basePath}?${qs}` : basePath;
}

export function clearFiltersHref(basePath: string): string {
  return basePath;
}
