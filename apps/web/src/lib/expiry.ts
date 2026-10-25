// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Expiry timestamps from `<input type="datetime-local">`.
 *
 * The input's value ("2026-10-27T09:00") carries no zone. Parsed on the server
 * it would be read in the *server's* zone (UTC in the container), not the
 * operator's, so the browser converts it to an absolute ISO timestamp before
 * submitting and the server only accepts that.
 */

/** Browser side: a datetime-local value, read in this browser's zone, as UTC ISO. Null when invalid. */
export function localDateTimeToIso(value: string): string | null {
  const trimmed = value.trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/.test(trimmed)) return null;
  const date = new Date(trimmed);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

const ISO_WITH_OFFSET =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})$/;

export type ParsedExpiry = { ok: true; expiresAt: string | null } | { ok: false; error: string };

/**
 * Server side: the submitted expiry. `iso` is the browser-converted value;
 * `local` is the raw input, present only to tell "left blank" apart from "the
 * conversion did not happen" (an invalid entry, or JavaScript not loaded).
 */
export function parseExpiresAt(iso: string | null | undefined, local?: string | null): ParsedExpiry {
  const value = iso?.trim() ?? "";
  if (!value) {
    return local?.trim()
      ? { ok: false, error: "Enter a valid expiry date and time, or leave it blank." }
      : { ok: true, expiresAt: null };
  }
  if (!ISO_WITH_OFFSET.test(value)) {
    return { ok: false, error: "Enter a valid expiry date and time, or leave it blank." };
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return { ok: false, error: "Enter a valid expiry date and time, or leave it blank." };
  }
  return { ok: true, expiresAt: date.toISOString() };
}
