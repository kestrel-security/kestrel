// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { FindingHref } from "@/components/findings/finding-link";
import { FindingProvenanceBrowser } from "@/components/findings/finding-provenance-browser";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import type { FindingEvidenceLink, FindingEvidenceRow } from "@/lib/types";

const GROUP_TITLES: Record<string, string> = {
  setting: "Configuration",
  identity: "Identity",
  grant: "Access grant",
  resource: "Resource",
  application: "Application",
  event: "Activity event",
  oauth_application: "OAuth application",
  other: "Other",
};

/** Titles already shown on the subject card — omit when repeated on every evidence row. */
const SUBJECT_CARD_LINK_TITLES = new Set([
  "findings for subject",
  "findings for this subject",
  "connector",
  "open connector",
  "open in provider",
]);

function formatEvidenceValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value, null, 2);
}

function normalizeLinkTitle(title: string): string {
  return title.replace(/→/g, "").trim().toLowerCase();
}

/** Drop links that already appear on the subject card when they repeat across rows. */
export function dedupeEvidenceLinks(
  evidence: FindingEvidenceRow[],
): Map<string, FindingEvidenceLink[]> {
  const hrefCounts = new Map<string, number>();
  for (const row of evidence) {
    for (const link of row.links ?? []) {
      hrefCounts.set(link.href, (hrefCounts.get(link.href) ?? 0) + 1);
    }
  }

  const result = new Map<string, FindingEvidenceLink[]>();
  for (const row of evidence) {
    const kept = (row.links ?? []).filter((link) => {
      const title = normalizeLinkTitle(link.title);
      const isSubjectCardLink = SUBJECT_CARD_LINK_TITLES.has(title);
      const repeats = (hrefCounts.get(link.href) ?? 0) > 1;
      if (isSubjectCardLink && repeats) return false;
      return true;
    });
    result.set(row.label, kept);
  }
  return result;
}

function groupEvidence(rows: FindingEvidenceRow[]): { group: string; rows: FindingEvidenceRow[] }[] {
  const order: string[] = [];
  const map = new Map<string, FindingEvidenceRow[]>();
  for (const row of rows) {
    const group = row.group || (row.label.includes(".") ? row.label.split(".", 1)[0] : "other");
    if (!map.has(group)) {
      order.push(group);
      map.set(group, []);
    }
    map.get(group)!.push(row);
  }
  // Prefer remediator-relevant groups first.
  const preferred = ["setting", "identity", "grant", "resource", "event", "application"];
  order.sort((a, b) => {
    const ai = preferred.indexOf(a);
    const bi = preferred.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
  return order.map((group) => {
    const groupRows = map.get(group)!;
    // Highlighted fields first so the violation reason is visible without scrolling.
    groupRows.sort((a, b) => Number(Boolean(b.highlight)) - Number(Boolean(a.highlight)));
    return { group, rows: groupRows };
  });
}

export function FindingEvidencePanel({
  findingId,
  evidence,
}: {
  findingId: string;
  evidence: FindingEvidenceRow[];
}) {
  const groups = groupEvidence(evidence);
  const linksByLabel = dedupeEvidenceLinks(evidence);

  return (
    <Card id="evidence">
      <CardHeader className="text-eyebrow">Evidence</CardHeader>
      <CardContent className="space-y-5">
        {evidence.length === 0 ? (
          <p className="text-sm text-muted-foreground">No evidence rows recorded for this finding.</p>
        ) : (
          groups.map(({ group, rows }) => (
            <div key={group}>
              <p className="mb-2 text-eyebrow">{GROUP_TITLES[group] ?? group}</p>
              <dl className="grid gap-2 sm:grid-cols-2">
                {rows.map((e) => {
                  const links = linksByLabel.get(e.label) ?? [];
                  const isComplex =
                    e.value !== null &&
                    e.value !== undefined &&
                    typeof e.value !== "string" &&
                    typeof e.value !== "number" &&
                    typeof e.value !== "boolean";
                  return (
                    <div
                      key={e.label}
                      className={`rounded-md px-2 py-1.5 ${
                        e.highlight ? "bg-amber-50/80 dark:bg-amber-950/30" : ""
                      } ${isComplex ? "sm:col-span-2" : ""}`}
                    >
                      <dt className="text-xs font-medium text-muted-foreground">
                        {e.display_label ?? e.label}
                      </dt>
                      <dd className="mt-0.5">
                        <pre
                          className={`whitespace-pre-wrap break-all font-mono text-sm ${
                            e.highlight ? "font-semibold" : ""
                          }`}
                        >
                          {formatEvidenceValue(e.value)}
                        </pre>
                        {links.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
                            {links.map((link) => (
                              <FindingHref
                                key={`${e.label}-${link.rel}-${link.href}`}
                                href={link.href}
                                className="text-primary underline"
                              >
                                {link.title}
                              </FindingHref>
                            ))}
                          </div>
                        )}
                      </dd>
                    </div>
                  );
                })}
              </dl>
            </div>
          ))
        )}
        <div className="border-t border-border pt-4">
          <p className="mb-2 text-eyebrow">Provider provenance</p>
          <FindingProvenanceBrowser findingId={findingId} />
        </div>
      </CardContent>
    </Card>
  );
}
