// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { PolicyEvaluationList } from "@/components/policies/policy-evaluation-list";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LocalTime } from "@/components/ui/local-time";
import { api, orFallback, segment } from "@/lib/api";
import { policyTabHref } from "@/lib/policy-tabs";
import type {
  PolicyDetail,
  PolicyEvaluationsResponse,
  PolicyOpenFindingsResponse,
} from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
const PREVIEW_LIMIT = 5;

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-eyebrow">{label}</dt>
      <dd className="mt-1 truncate text-sm">{children}</dd>
    </div>
  );
}

/**
 * Overview tab — the "what is this policy and is it working?" answer.
 *
 * Leads with `policy.description`, which the previous layout fetched but never
 * rendered anywhere, leaving the Python source as the only way to learn what a
 * policy actually detects.
 */
export async function PolicyOverviewTab({
  policy,
  policyId,
}: {
  policy: PolicyDetail;
  policyId: string;
}) {
  const [openFindings, evaluations] = await Promise.all([
    api
      .get<PolicyOpenFindingsResponse>(`/policies/${segment(policyId)}/findings?limit=${PREVIEW_LIMIT}`)
      .catch(orFallback(null)),
    api
      .get<PolicyEvaluationsResponse>(`/policies/${segment(policyId)}/evaluations?limit=${PREVIEW_LIMIT}`)
      .catch(orFallback(null)),
  ]);

  const frameworks = Object.keys(policy.compliance_mappings ?? {});

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>What this detects</CardTitle>
        </CardHeader>
        <CardContent>
          {policy.description ? (
            <p className="max-w-3xl whitespace-pre-wrap text-sm leading-relaxed">
              {policy.description}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">
              No description provided. Add a{" "}
              <code className="rounded bg-muted px-1 font-mono text-xs">DESCRIPTION</code> string to
              the policy source so operators can tell what this checks without reading the code.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>At a glance</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
            <Fact label="Severity">
              {policy.severity ? <SeverityBadge severity={policy.severity} /> : "—"}
            </Fact>
            <Fact label="Status">
              {policy.is_enabled === true ? (
                <StatusBadge status="enabled" />
              ) : policy.is_enabled === false ? (
                <StatusBadge status="disabled" />
              ) : (
                "—"
              )}
            </Fact>
            <Fact label="Resource type">
              {policy.resource_type ? (
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                  {policy.resource_type}
                </code>
              ) : (
                "—"
              )}
            </Fact>
            <Fact label="Open findings">
              {policy.open_finding_count > 0 ? (
                <Link
                  href={policyTabHref(policyId, "findings")}
                  className="font-medium text-primary hover:underline"
                >
                  {policy.open_finding_count}
                </Link>
              ) : (
                <span className="text-muted-foreground">0</span>
              )}
            </Fact>
            <Fact label="Source">
              {policy.source}
              {policy.pack_name ? (
                <span className="text-muted-foreground"> · {policy.pack_name}</span>
              ) : null}
            </Fact>
            <Fact label="Version">
              {policy.version != null ? (
                <Link
                  href={policyTabHref(policyId, "versions")}
                  className="text-primary hover:underline"
                >
                  v{policy.version}
                </Link>
              ) : (
                "—"
              )}
            </Fact>
            <Fact label="Last evaluated">
              <LocalTime value={policy.last_evaluated_at} fallback="Never" className="tabular-nums" />
            </Fact>
            <Fact label="Last result">
              {policy.last_evaluation_status ? (
                <StatusBadge status={policy.last_evaluation_status} />
              ) : (
                <span className="text-xs text-muted-foreground">never run</span>
              )}
            </Fact>
          </dl>
        </CardContent>
      </Card>

      {policy.remediation ? (
        <Card>
          <CardHeader>
            <CardTitle>Remediation</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="max-w-3xl whitespace-pre-wrap text-sm leading-relaxed">
              {policy.remediation}
            </p>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Compliance mappings</CardTitle>
        </CardHeader>
        <CardContent>
          {frameworks.length === 0 ? (
            <p className="text-sm text-muted-foreground">No compliance mappings.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {Object.entries(policy.compliance_mappings).map(([framework, controls]) => (
                <li key={framework} className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono font-medium uppercase">{framework}</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {controls.join(", ")}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle>Open findings</CardTitle>
          <Link
            href={policyTabHref(policyId, "findings")}
            className="text-sm font-normal text-primary hover:underline"
          >
            View all →
          </Link>
        </CardHeader>
        <CardContent className="space-y-3">
          {!openFindings ? (
            <p className="text-sm text-muted-foreground">
              Open findings are unavailable right now.
            </p>
          ) : !openFindings.ever_evaluated ? (
            <p className="text-sm text-muted-foreground">
              This policy has never been evaluated. Use Evaluate now, or run an integration sync.
            </p>
          ) : openFindings.open_finding_count === 0 ? (
            <p className="text-sm text-muted-foreground">
              No open findings — the last evaluation produced a clean result (or findings were
              resolved).
            </p>
          ) : (
            <>
              <div className="flex flex-wrap gap-3 text-sm">
                <span className="tabular-nums text-muted-foreground">
                  <span className="font-medium text-foreground">
                    {openFindings.open_finding_count}
                  </span>{" "}
                  open
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
              </div>
              <ul className="divide-y divide-border rounded-md border border-border text-sm">
                {openFindings.open_findings.map((f) => (
                  <li key={f.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                    <SeverityBadge severity={f.severity} />
                    <Link href={f.detail_path} className="font-medium text-primary hover:underline">
                      {f.title}
                    </Link>
                    <span className="text-muted-foreground">
                      {f.subject_label ?? `${f.subject_type} ${f.subject_id.slice(0, 8)}…`}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle>Recent evaluations</CardTitle>
          <Link
            href={policyTabHref(policyId, "evaluations")}
            className="text-sm font-normal text-primary hover:underline"
          >
            View all →
          </Link>
        </CardHeader>
        <CardContent>
          <PolicyEvaluationList items={evaluations?.items ?? []} policyId={policyId} preview />
        </CardContent>
      </Card>
    </div>
  );
}
