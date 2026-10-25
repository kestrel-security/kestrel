// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, orFallback, segment } from "@/lib/api";
import { policyTabHref } from "@/lib/policy-tabs";
import type { PolicyOpenFindingsResponse } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
const LIMIT = 25;

/**
 * Findings tab — the open findings this policy is currently producing.
 *
 * Replaces the cramped five-row list that used to sit in a half-width card with
 * a real table at full width.
 */
export async function PolicyFindingsTab({ policyId }: { policyId: string }) {
  const openFindings = await api
    .get<PolicyOpenFindingsResponse>(`/policies/${segment(policyId)}/findings?limit=${LIMIT}`)
    .catch(orFallback(null));

  if (!openFindings) {
    return (
      <EmptyState
        title="Open findings are unavailable"
        hint="The findings API could not be reached. Try again, or check API health."
      />
    );
  }

  if (!openFindings.ever_evaluated) {
    return (
      <EmptyState
        title="This policy has never been evaluated"
        hint="Run it against live inventory with Evaluate now, or wait for the next integration sync."
      />
    );
  }

  if (openFindings.open_finding_count === 0) {
    return (
      <EmptyState
        title="No open findings"
        hint="The last evaluation produced a clean result, or every finding has been resolved."
        action={
          <Button asChild size="sm" variant="outline">
            <Link href={policyTabHref(policyId, "evaluations")}>View evaluation history</Link>
          </Button>
        }
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="tabular-nums text-muted-foreground">
          <span className="font-medium text-foreground">{openFindings.open_finding_count}</span> open
        </span>
        {SEVERITY_ORDER.map((sev) => {
          const count = openFindings.open_by_severity?.[sev] ?? 0;
          if (count === 0) return null;
          return (
            <span key={sev} className="inline-flex items-center gap-1.5">
              <SeverityBadge severity={sev} />
              <span className="tabular-nums text-muted-foreground">{count}</span>
            </span>
          );
        })}
        <Link
          href={openFindings.findings_list_path}
          className="ml-auto text-sm text-primary hover:underline"
        >
          Open in Findings →
        </Link>
      </div>

      <Card className="overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <Table>
            <TableHeader>
              <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
                <TableHead>Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Subject</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {openFindings.open_findings.map((f) => (
                <TableRow key={f.id}>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell>
                    <Link href={f.detail_path} className="font-medium hover:underline">
                      {f.title}
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {f.subject_label ?? (
                      <span className="font-mono text-xs">
                        {f.subject_type} {f.subject_id.slice(0, 8)}…
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Card>

      {openFindings.open_findings_truncated ? (
        <p className="text-xs text-muted-foreground">
          Showing {openFindings.open_findings.length} of {openFindings.open_finding_count}.{" "}
          <Link href={openFindings.findings_list_path} className="text-primary hover:underline">
            View all in Findings →
          </Link>
        </p>
      ) : null}
    </div>
  );
}
