// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEffect, useState } from "react";

import { absoluteTime, relativeTime } from "@/lib/utils";

type Format = "datetime" | "date" | "relative";

/** Deterministic UTC rendering: identical on the server and in the browser. */
export function utcTime(value: string | Date, format: Format): string {
  const iso = (value instanceof Date ? value : new Date(value)).toISOString();
  return format === "date" ? iso.slice(0, 10) : `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

function localTime(date: Date, format: Format): string {
  if (format === "relative") return relativeTime(date);
  if (format === "date") {
    return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  return absoluteTime(date) ?? "";
}

/**
 * A timestamp in the viewer's timezone and locale. The server knows neither,
 * so it renders a fixed UTC form and the browser swaps in the local one after
 * hydration. Formatting with `toLocaleString()` during render instead makes
 * the server and browser disagree, which React reports as a hydration error.
 */
export function LocalTime({
  value,
  format = "datetime",
  fallback = "—",
  className,
}: {
  value: string | Date | null | undefined;
  format?: Format;
  fallback?: string;
  className?: string;
}) {
  const date = value ? (value instanceof Date ? value : new Date(value)) : null;
  const valid = date !== null && !Number.isNaN(date.getTime());
  const iso = valid ? date.toISOString() : "";
  const [local, setLocal] = useState<{ text: string; title: string } | null>(null);

  useEffect(() => {
    if (!iso) return;
    const parsed = new Date(iso);
    setLocal({ text: localTime(parsed, format), title: absoluteTime(parsed) ?? iso });
  }, [iso, format]);

  if (!valid) return <span className={className}>{fallback}</span>;
  return (
    <time dateTime={iso} title={local?.title ?? iso} className={className}>
      {local?.text ?? utcTime(iso, format)}
    </time>
  );
}
