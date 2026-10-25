// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { PolicyEvaluationList } from "@/components/policies/policy-evaluation-list";
import { Card, CardContent } from "@/components/ui/card";
import { api, orFallback, segment } from "@/lib/api";
import { policyTabHref } from "@/lib/policy-tabs";
import type { PolicyEvaluationsResponse } from "@/lib/types";

/** API cap for the evaluation log. */
const FULL_LOG_LIMIT = 100;

/**
 * Evaluations tab — the full run history.
 *
 * This absorbs the old standalone `/policies/{id}/evaluations` route, which now
 * redirects here so there is a single canonical destination.
 */
export async function PolicyEvaluationsTab({ policyId }: { policyId: string }) {
  const evaluations = await api
    .get<PolicyEvaluationsResponse>(`/policies/${segment(policyId)}/evaluations?limit=${FULL_LOG_LIMIT}`)
    .catch(orFallback(null));

  const items = evaluations?.items ?? [];
  const atCap = items.length >= FULL_LOG_LIMIT;

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <PolicyEvaluationList
          items={items}
          policyId={policyId}
          emptyHint={
            <>
              No evaluations yet. Use Evaluate now, run an integration sync, or{" "}
              <Link href={policyTabHref(policyId, "code")} className="text-primary hover:underline">
                dry-run it in the editor
              </Link>{" "}
              without writing findings.
            </>
          }
        />
        {atCap ? (
          <p className="text-xs text-muted-foreground">
            Showing the latest {FULL_LOG_LIMIT} evaluations.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
