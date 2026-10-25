// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}


const RELATIVE_UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 60 * 60 * 1000],
  ["month", 30 * 24 * 60 * 60 * 1000],
  ["week", 7 * 24 * 60 * 60 * 1000],
  ["day", 24 * 60 * 60 * 1000],
  ["hour", 60 * 60 * 1000],
  ["minute", 60 * 1000],
];

/**
 * "4 minutes ago" for a timestamp. Everything in the product is a point in
 * the recent past -- a sync, a login, a finding -- and an ISO string makes
 * the reader do the arithmetic. Pair with `title={iso}` for the exact value.
 */
export function relativeTime(
  value: string | Date | null | undefined,
  now: Date = new Date(),
  fallback = "—",
): string {
  if (!value) return fallback;
  const then = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(then.getTime())) return fallback;
  const deltaMs = then.getTime() - now.getTime();
  const absMs = Math.abs(deltaMs);
  if (absMs < 45_000) return "just now";
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, ms] of RELATIVE_UNITS) {
    if (absMs >= ms) return formatter.format(Math.round(deltaMs / ms), unit);
  }
  return formatter.format(Math.round(deltaMs / 1000), "second");
}


/** Full local timestamp for a `title` attribute, so the exact value is one hover away. */
export function absoluteTime(value: string | Date | null | undefined): string | undefined {
  if (!value) return undefined;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
