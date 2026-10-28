// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Pure helpers for the policy workbench's Generate with AI card: how the scope
 * selection turns into a request, and how the generator's analysis and
 * assessability come back as text. Dependency-free so it can be unit-tested.
 */

import type {
  PolicyGenerateAssessability,
  PolicyGenerateIntentAnalysis,
  PolicyGenerateScope,
} from "@/lib/types";

export const SCOPE_OPTIONS: { value: PolicyGenerateScope; label: string; hint: string }[] = [
  {
    value: "single_app",
    label: "One connected app",
    hint: "The policy scopes itself to the selected application.",
  },
  {
    value: "cross_app",
    label: "All connected apps",
    hint: "The policy reads every application and the same person's accounts across them (cluster).",
  },
];

/** The connector hint and scope to send for the operator's selection. */
export function scopeForRequest(
  scope: PolicyGenerateScope,
  selectedConnector: string | undefined,
): { scope: PolicyGenerateScope; connector_hint: string | undefined } {
  if (scope === "cross_app") {
    // The selected app, if any, is the focus (usually the identity provider);
    // the pseudo-connector is only needed when nothing is selected.
    return { scope, connector_hint: selectedConnector ?? "cross_app" };
  }
  return { scope, connector_hint: selectedConnector };
}

export function describeScope(analysis: PolicyGenerateIntentAnalysis | null | undefined): string {
  if (!analysis) return "";
  const where = analysis.scope === "cross_app" ? "every connected app" : "one app";
  const focus = analysis.focus_connector ? ` (focus: ${analysis.focus_connector})` : "";
  return `${where}${focus} — ${analysis.scope_reason}`;
}

/** One line per condition the generator read, for the analysis callout. */
export function describeIntentAnalysis(analysis: PolicyGenerateIntentAnalysis | null | undefined): string[] {
  if (!analysis) return [];
  const lines: string[] = [];
  const subject = Object.entries(analysis.subject)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(", ");
  if (subject) lines.push(`Subject: ${subject}`);
  if (analysis.conditions.length) lines.push(`Conditions: ${analysis.conditions.join(", ")}`);
  if (analysis.days !== null) lines.push(`Threshold: ${analysis.days} days`);
  lines.push(`Finding per ${analysis.per}`);
  if (analysis.requires.length) lines.push(`REQUIRES: ${analysis.requires.join(", ")}`);
  return lines;
}

/** "Not assessable in GitHub (acme): identity:last_sign_in" or "" when every app can assess. */
export function summarizeAssessability(rows: PolicyGenerateAssessability[] | null | undefined): string {
  if (!rows || rows.length === 0) return "";
  const blocked = rows.filter((row) => !row.assessable);
  if (blocked.length === 0) return `Assessable in all ${rows.length} connected app${rows.length === 1 ? "" : "s"}.`;
  return blocked
    .map((row) => `Not assessable in ${row.name}: ${row.missing.join(", ")}`)
    .join(" · ");
}
