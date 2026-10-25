// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Dashboard chart palette — muted tone tokens from globals.css / UI_STYLE_GUIDE.md */

export type ChartColorKind = "severity" | "health" | "status" | "generic";

/** Severity: semantic risk tones; low uses brand blue (not success green). */
export const SEVERITY_TONES: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

/** Connector / integration health — semantic. */
export const HEALTH_TONES: Record<string, string> = {
  healthy: "success",
  failed: "critical",
  stale: "medium",
  never: "neutral",
  never_synced: "neutral",
  running: "info",
};

/** Finding status — brand-forward (open is primary violet, not alarm red). */
export const STATUS_TONES: Record<string, string> = {
  open: "primary",
  resolved: "success",
  suppressed: "neutral",
  exception: "info",
  muted: "low",
};

/** Static fill classes — written literally so Tailwind emits the utilities. */
const FILL_TONE_CLASSES: Record<string, string> = {
  critical: "fill-tone-critical",
  high: "fill-tone-high",
  medium: "fill-tone-medium",
  low: "fill-tone-low",
  info: "fill-tone-info",
  success: "fill-tone-success",
  neutral: "fill-tone-neutral",
  primary: "fill-primary",
};

/** Static dot classes for chart legends. */
const DOT_TONE_CLASSES: Record<string, string> = {
  critical: "bg-tone-critical",
  high: "bg-tone-high",
  medium: "bg-tone-medium",
  low: "bg-tone-low",
  info: "bg-tone-info",
  success: "bg-tone-success",
  neutral: "bg-tone-neutral",
  primary: "bg-primary",
};

/** Ordered product data series — violet → periwinkle → blue. */
export const BRAND_SERIES_FILL = [
  "fill-primary",
  "fill-tone-info",
  "fill-tone-low",
  "fill-tone-neutral",
  "fill-muted-foreground",
] as const;

export const BRAND_SERIES_DOT = [
  "bg-primary",
  "bg-tone-info",
  "bg-tone-low",
  "bg-tone-neutral",
  "bg-muted-foreground",
] as const;

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

function resolveToneKey(name: string, kind: ChartColorKind): string {
  const key = name.toLowerCase();
  if (kind === "severity" || key in SEVERITY_TONES) {
    return SEVERITY_TONES[key] ?? "critical";
  }
  if (kind === "health" || key in HEALTH_TONES) {
    return HEALTH_TONES[key] ?? "neutral";
  }
  if (kind === "status" || key in STATUS_TONES) {
    return STATUS_TONES[key] ?? "neutral";
  }
  return "primary";
}

function isKnownCategory(name: string): boolean {
  const key = name.toLowerCase();
  return (
    key in SEVERITY_TONES ||
    key in HEALTH_TONES ||
    key in STATUS_TONES
  );
}

export function chartFillClassFor(
  name: string,
  kind: ChartColorKind = "generic",
): string {
  if (kind === "generic" && !isKnownCategory(name)) {
    return BRAND_SERIES_FILL[Math.abs(hash(name)) % BRAND_SERIES_FILL.length];
  }
  const tone = resolveToneKey(name, kind);
  return FILL_TONE_CLASSES[tone] ?? FILL_TONE_CLASSES.primary;
}

export function chartDotClassFor(
  name: string,
  kind: ChartColorKind = "generic",
): string {
  if (kind === "generic" && !isKnownCategory(name)) {
    return BRAND_SERIES_DOT[Math.abs(hash(name)) % BRAND_SERIES_DOT.length];
  }
  const tone = resolveToneKey(name, kind);
  return DOT_TONE_CLASSES[tone] ?? DOT_TONE_CLASSES.primary;
}

export function inferChartKind(
  series: { name: string }[],
): ChartColorKind {
  const names = series.map((s) => s.name.toLowerCase());
  if (names.some((n) => n in SEVERITY_TONES)) return "severity";
  if (names.some((n) => n in HEALTH_TONES)) return "health";
  if (names.some((n) => n in STATUS_TONES)) return "status";
  return "generic";
}

/** Human-readable category label for chart axes and legends. */
export function formatChartCategory(name: string): string {
  return name
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
