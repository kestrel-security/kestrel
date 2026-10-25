// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import {
  Bell,
  BellOff,
  CheckCircle2,
  Clock,
  RotateCcw,
  ShieldOff,
  UserCheck,
} from "lucide-react";

import { CreateFindingTicketPanel } from "@/components/findings/create-finding-ticket-panel";
import { FindingActionForm, type FindingActionResult } from "@/components/findings/finding-action-form";
import { FindingHref } from "@/components/findings/finding-link";
import { VerifyRemediationButton } from "@/components/findings/verify-remediation-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { LocalTime } from "@/components/ui/local-time";
import type { FindingDetail, Operator, TicketIntegration } from "@/lib/types";

type FormAction = (formData: FormData) => Promise<FindingActionResult>;
type VoidAction = () => Promise<FindingActionResult>;

const selectClass =
  "min-w-0 rounded-md border border-input bg-background px-2 py-1.5 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50";
const inputClass =
  "min-w-[8rem] flex-1 rounded-md border border-input bg-background px-2 py-1.5 text-sm text-foreground shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function FindingActionRail({
  finding,
  findingId,
  operators,
  ticketIntegrations,
  canCreateTickets,
  resolveAction,
  reopenAction,
  suppressAction,
  muteAction,
  unmuteAction,
  assignAction,
  watchAction,
  unwatchAction,
}: {
  finding: FindingDetail;
  findingId: string;
  operators: Operator[];
  ticketIntegrations: TicketIntegration[];
  canCreateTickets: boolean;
  resolveAction: VoidAction;
  reopenAction: VoidAction;
  suppressAction: VoidAction;
  muteAction: FormAction;
  unmuteAction: VoidAction;
  assignAction: FormAction;
  watchAction: VoidAction;
  unwatchAction: VoidAction;
}) {
  const complianceEntries = Object.entries(finding.policy?.compliance_mappings ?? {});
  const complianceControls = finding.policy?.compliance_controls ?? [];

  return (
    <div className="space-y-6 lg:sticky lg:top-4 lg:self-start">
      <Card>
        <CardHeader className="text-eyebrow">Status &amp; Ownership</CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {finding.status !== "resolved" ? (
              <FindingActionForm action={resolveAction}>
                <Button type="submit" size="sm">
                  <CheckCircle2 aria-hidden />
                  Mark Resolved
                </Button>
              </FindingActionForm>
            ) : null}
            {finding.status !== "open" ? (
              <FindingActionForm action={reopenAction}>
                <Button type="submit" size="sm" variant="outline">
                  <RotateCcw aria-hidden />
                  Reopen
                </Button>
              </FindingActionForm>
            ) : null}
            {finding.status !== "suppressed" ? (
              <FindingActionForm action={suppressAction}>
                <Button type="submit" size="sm" variant="outline">
                  <ShieldOff aria-hidden />
                  Suppress
                </Button>
              </FindingActionForm>
            ) : null}
            {finding.status === "muted" ? (
              <FindingActionForm action={unmuteAction}>
                <Button type="submit" size="sm" variant="outline">
                  <Bell aria-hidden />
                  Unmute
                </Button>
              </FindingActionForm>
            ) : null}
          </div>
          {finding.status === "muted" && finding.muted_until ? (
            <p className="text-sm text-muted-foreground">
              Muted until <LocalTime value={finding.muted_until} />
              {finding.mute_reason ? ` · ${finding.mute_reason}` : ""}
              {new Date(finding.muted_until).getTime() <= Date.now()
                ? " · expiry passed — unmute or triage"
                : ""}
            </p>
          ) : (
            <FindingActionForm
              action={muteAction}
              className="flex flex-wrap items-end gap-2 border-t border-border pt-4"
            >
              <p className="w-full text-sm font-medium">Mute / snooze (temporary)</p>
              <p className="w-full text-xs text-muted-foreground">
                Distinct from permanent suppress and accepted-risk exceptions. Requires an expiry.
              </p>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted-foreground">Duration</span>
                <select name="days" defaultValue="7" className={selectClass}>
                  <option value="1">1 day</option>
                  <option value="7">7 days</option>
                  <option value="30">30 days</option>
                </select>
              </label>
              <input name="reason" aria-label="Mute note (optional)" placeholder="Optional note" className={inputClass} />
              <Button type="submit" size="sm" variant="outline">
                <Clock aria-hidden />
                Mute
              </Button>
            </FindingActionForm>
          )}
          <FindingActionForm action={assignAction} className="flex flex-col flex-wrap gap-2 sm:flex-row">
            <select
              name="assigned_to_operator_id"
              defaultValue={finding.assigned_to?.id ?? ""}
              aria-label="Assign to operator"
              className={`flex-1 ${selectClass}`}
            >
              <option value="">Unassigned</option>
              {operators.map((op) => (
                <option key={op.id} value={op.id}>
                  {op.display_name ?? op.email}
                </option>
              ))}
            </select>
            <Button type="submit" size="sm" variant="outline">
              <UserCheck aria-hidden />
              Assign
            </Button>
          </FindingActionForm>
          <div className="border-t border-border pt-4">
            <p className="text-sm font-medium">Watch for updates</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Get in-app notifications when this finding opens or resolves — distinct from
              assignment and mute. Channel mute in Settings still applies.
            </p>
            {finding.watching ? (
              <FindingActionForm action={unwatchAction} className="mt-2">
                <Button type="submit" size="sm" variant="outline">
                  <BellOff aria-hidden />
                  Unwatch
                </Button>
              </FindingActionForm>
            ) : (
              <FindingActionForm action={watchAction} className="mt-2">
                <Button type="submit" size="sm" variant="outline">
                  <Bell aria-hidden />
                  Watch
                </Button>
              </FindingActionForm>
            )}
          </div>
        </CardContent>
      </Card>

      <Card id="tickets">
        <CardHeader className="text-eyebrow">Tickets</CardHeader>
        <CardContent>
          <CreateFindingTicketPanel
            findingId={findingId}
            tickets={finding.tickets ?? []}
            integrations={ticketIntegrations}
            canCreate={canCreateTickets}
          />
        </CardContent>
      </Card>

      <Card id="remediation">
        <CardHeader className="text-eyebrow">Remediation</CardHeader>
        <CardContent className="space-y-3 text-sm">
          {finding.policy?.remediation ? (
            <p>{finding.policy.remediation}</p>
          ) : (
            <p className="text-muted-foreground">
              No remediation guidance on this policy version. Update the policy&apos;s{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono">remediation</code> field, or
              document the fix path in an exception.
            </p>
          )}
          {(finding.subject.provider_console_url || finding.subject.connector_path) && (
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              <FindingHref href={finding.subject.provider_console_url}>
                {finding.subject.provider_console_label ?? "Open in provider"} →
              </FindingHref>
              <FindingHref href={finding.subject.connector_path}>Open integration →</FindingHref>
            </div>
          )}
          {(finding.remediation_playbook ?? []).length > 0 && (
            <div className="border-t border-border pt-3">
              <p className="mb-2 font-medium">Playbook</p>
              <ol className="space-y-3">
                {finding.remediation_playbook!.map((step, index) => (
                  <li key={step.id} className="flex gap-3">
                    <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium tabular-nums">
                      {index + 1}
                    </span>
                    <div className="min-w-0 space-y-0.5">
                      <p className="font-medium">
                        {step.title}
                        <span className="ml-2 text-eyebrow font-normal">{step.kind}</span>
                      </p>
                      <p className="text-muted-foreground">{step.instruction}</p>
                      {step.href ? (
                        <FindingHref href={step.href} className="text-xs text-primary underline">
                          Open →
                        </FindingHref>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          )}
          <VerifyRemediationButton findingId={finding.id} />
          {finding.policy?.id && (
            <p>
              Policy:{" "}
              <Link href={`/policies/${finding.policy.id}`} className="font-medium hover:underline">
                {finding.policy.title ?? finding.policy.slug}
              </Link>
              {finding.policy.version != null ? ` · v${finding.policy.version}` : ""}
              {finding.policy.is_system_toxic ? (
                <span className="ml-2 text-xs text-muted-foreground">(toxic combination)</span>
              ) : null}
            </p>
          )}
          {finding.policy?.description && (
            <p className="text-muted-foreground">{finding.policy.description}</p>
          )}
          {(complianceControls.length > 0 || complianceEntries.length > 0) && (
            <div className="border-t border-border pt-3">
              <p className="mb-1 font-medium">Compliance mappings</p>
              {complianceControls.length > 0 ? (
                <ul className="space-y-1 text-sm text-muted-foreground">
                  {complianceControls.map((c) => (
                    <li key={`${c.framework}-${c.control_id}-${c.id ?? "unresolved"}`}>
                      <span className="font-medium text-foreground">{c.framework}</span>{" "}
                      {c.control_id}
                      {c.title ? ` — ${c.title}` : ""}
                    </li>
                  ))}
                </ul>
              ) : (
                <ul className="space-y-1 text-muted-foreground">
                  {complianceEntries.map(([framework, controls]) => (
                    <li key={framework}>
                      {framework}: {controls.join(", ")}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
