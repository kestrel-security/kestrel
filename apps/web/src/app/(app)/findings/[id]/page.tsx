// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound } from "next/navigation";
import { NotebookPen, ShieldCheck } from "lucide-react";

import { AppMark } from "@/components/brand/app-mark";
import { FindingActionForm, type FindingActionResult } from "@/components/findings/finding-action-form";
import { FindingActionRail } from "@/components/findings/finding-action-rail";
import {
  FindingDetailHeader,
  type FindingJumpLink,
} from "@/components/findings/finding-detail-header";
import { FindingEvidencePanel } from "@/components/findings/finding-evidence-panel";
import { inAppFindingLink } from "@/components/findings/finding-link";
import { FindingSubjectCard } from "@/components/findings/finding-subject-card";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { LocalTime } from "@/components/ui/local-time";
import { Textarea } from "@/components/ui/textarea";
import { apiStatePage } from "@/components/api-state";
import { ApiError, api, segment } from "@/lib/api";
import { resolveAppMarkFromNode, resolveAppMark } from "@/lib/app-mark";
import {
  assignFinding,
  createFindingException,
  addFindingNote,
  muteFinding,
  unmuteFinding,
  updateFindingStatus,
} from "@/lib/actions/findings";
import { unwatchFinding, watchFinding } from "@/lib/actions/notifications";
import { parseExpiresAt } from "@/lib/expiry";
import type { FindingDetail, Operator, TicketIntegration } from "@/lib/types";
import { countOf } from "@/lib/plural";

// The mutations below return {ok, error} rather than throwing, so a 4xx (a
// Read-only operator's 403, a validation error) shows next to the form that
// caused it instead of replacing the page with the error boundary.

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let finding: FindingDetail;
  try {
    finding = await api.get<FindingDetail>(`/findings/${segment(id)}`);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError) {
      return (
        <div className="mx-auto max-w-6xl">
          <EmptyState
            title="Could not load this finding"
            hint={`${error.status}: request failed. Try again, or return to Findings.`}
          />
          <p className="mt-4 text-center text-sm">
            <Link href="/findings" className="text-primary underline">
              Back to Findings
            </Link>
          </p>
        </div>
      );
    }
    throw error;
  }
  // Any authenticated operator can list teammates (read_only minimum) --
  // needed here to populate the assignment picker.
  const operators = await api.get<Operator[]>("/operators");
  const me = await api.get<Operator>("/auth/me");
  let ticketIntegrations: TicketIntegration[] = [];
  try {
    ticketIntegrations = await api.get<TicketIntegration[]>("/ticket-integrations");
  } catch (error) {
    // Analyst+ can list; if the route is unavailable, keep handoff-only UX.
    if (!(error instanceof ApiError && (error.status === 403 || error.status === 404))) {
      throw error;
    }
  }

  async function resolveAction(): Promise<FindingActionResult> {
    "use server";
    return updateFindingStatus(id, "resolved");
  }
  async function reopenAction(): Promise<FindingActionResult> {
    "use server";
    return updateFindingStatus(id, "open");
  }
  async function suppressAction(): Promise<FindingActionResult> {
    "use server";
    return updateFindingStatus(id, "suppressed");
  }
  async function assignAction(formData: FormData): Promise<FindingActionResult> {
    "use server";
    const raw = formData.get("assigned_to_operator_id");
    const assigneeId = typeof raw === "string" && raw ? raw : null;
    return assignFinding(id, assigneeId);
  }
  async function exceptionAction(formData: FormData): Promise<FindingActionResult> {
    "use server";
    const reason = String(formData.get("reason") ?? "").trim();
    if (!reason) return { ok: false, error: "Enter a reason for the exception." };
    // The browser converts the datetime-local value to an absolute timestamp
    // in the operator's zone (FindingActionForm); never re-parse it here.
    const expiry = parseExpiresAt(
      String(formData.get("expires_at") ?? ""),
      String(formData.get("expires_at_local") ?? ""),
    );
    if (!expiry.ok) return expiry;
    return createFindingException(id, reason, expiry.expiresAt);
  }
  async function noteAction(formData: FormData): Promise<FindingActionResult> {
    "use server";
    const body = String(formData.get("body") ?? "").trim();
    if (!body) return { ok: false, error: "Write a note first." };
    return addFindingNote(id, body);
  }
  async function muteAction(formData: FormData): Promise<FindingActionResult> {
    "use server";
    const daysRaw = String(formData.get("days") ?? "").trim();
    const reason = String(formData.get("reason") ?? "").trim() || null;
    const days = daysRaw ? Number(daysRaw) : 7;
    if (!Number.isInteger(days) || days <= 0) return { ok: false, error: "Choose a mute duration." };
    return muteFinding(id, { days, reason });
  }
  async function unmuteAction(): Promise<FindingActionResult> {
    "use server";
    return unmuteFinding(id);
  }
  async function watchAction(): Promise<FindingActionResult> {
    "use server";
    return watchFinding(id);
  }
  async function unwatchAction(): Promise<FindingActionResult> {
    "use server";
    return unwatchFinding(id);
  }

  const subjectLabel =
    finding.subject.label ?? `${finding.subject.type} ${finding.subject.id.slice(0, 8)}…`;

  const hasRelated = (finding.related_findings ?? []).length > 0;
  const hasCohort =
    Boolean(finding.same_policy_cohort) &&
    (finding.same_policy_cohort?.total_other_count ?? 0) > 0;
  const hasBlastRadius =
    (finding.blast_radius?.open_finding_count ?? 0) > 0 ||
    Boolean(finding.blast_radius?.subject_node_id);

  const jumpLinks: FindingJumpLink[] = [
    { href: "#subject", label: "Subject" },
    { href: "#evidence", label: "Evidence" },
    { href: "#remediation", label: "Remediation" },
    { href: "#attack-path", label: "Attack path" },
    ...(hasBlastRadius ? [{ href: "#blast-radius", label: "Blast radius" }] : []),
    ...(hasRelated || hasCohort ? [{ href: "#related", label: "Related" }] : []),
    { href: "#activity", label: "Activity" },
    { href: "#notes", label: "Notes" },
    { href: "#exceptions", label: "Exceptions" },
  ];

  const attackPathCard = (
    <Card id="attack-path">
      <CardHeader>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span className="flex flex-wrap items-baseline gap-2">
            <span className="text-eyebrow">Attack path</span>
            {finding.attack_path && finding.attack_path.hop_count > 0 ? (
              <span className="text-xs normal-case tracking-normal text-muted-foreground">
                {countOf(finding.attack_path.hop_count, "hop")} (existing edges only)
              </span>
            ) : null}
          </span>
          <a
            href={`/api/findings/${id}/blast-radius/export?format=json`}
            className="text-sm font-normal text-primary underline"
          >
            Export with blast radius →
          </a>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {finding.attack_path?.summary ? (
          <p className="text-muted-foreground">{finding.attack_path.summary}</p>
        ) : (
          <p className="text-muted-foreground">
            No attack path available for this subject (missing graph node or no privilege-relevant
            edges within depth).
          </p>
        )}
        {(finding.attack_path?.hops ?? []).length > 0 ? (
          <ol className="list-decimal space-y-2 pl-5">
            {finding.attack_path!.hops.map((hop) => {
              const sourceMark = resolveAppMarkFromNode({
                nodeType: hop.source.node_type,
                label: hop.source.label,
                properties: hop.source.properties,
              });
              const targetMark = resolveAppMarkFromNode({
                nodeType: hop.target.node_type,
                label: hop.target.label,
                properties: hop.target.properties,
              });
              return (
                <li key={`${hop.edge_id}-${hop.order}`}>
                  <p>{hop.explanation}</p>
                  <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                    <span>
                      {hop.edge_type}
                      {hop.access_path ? ` · ${hop.access_path}` : ""}
                      {" · "}
                    </span>
                    <AppMark mark={sourceMark} size={12} />
                    <span>{hop.source.label}</span>
                    <span aria-hidden>→</span>
                    <AppMark mark={targetMark} size={12} />
                    <span>{hop.target.label}</span>
                  </p>
                </li>
              );
            })}
          </ol>
        ) : null}
        {finding.policy?.is_system_toxic ? (
          <p className="text-xs text-muted-foreground">
            Toxic combination finding — path prefers privilege sinks (roles, OAuth apps, resources).
          </p>
        ) : null}
      </CardContent>
    </Card>
  );

  const blastRadiusCard =
    (finding.blast_radius?.open_finding_count ?? 0) > 0 ? (
      <Card id="blast-radius">
        <CardHeader>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="flex flex-wrap items-baseline gap-2">
              <span className="text-eyebrow">Blast radius</span>
              <span className="text-xs normal-case tracking-normal text-muted-foreground">
                {finding.blast_radius!.open_finding_count} open on graph neighbors (depth{" "}
                {finding.blast_radius!.depth})
              </span>
            </span>
            <span className="flex gap-3 text-sm font-normal">
              <a
                href={`/api/findings/${id}/blast-radius/export?format=csv`}
                className="text-primary underline"
              >
                Export CSV
              </a>
              <a
                href={`/api/findings/${id}/blast-radius/export?format=json`}
                className="text-primary underline"
              >
                Export JSON
              </a>
            </span>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {(finding.blast_radius!.neighbors ?? []).length > 0 && (
            <ul className="space-y-3">
              {finding.blast_radius!.neighbors.map((n) => (
                <li key={n.node_id} className="text-sm">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <AppMark
                      mark={resolveAppMark({
                        applicationType: n.application_type,
                        nodeType: n.node_type,
                        label: n.label,
                      })}
                      size={14}
                    />
                    <span className="text-muted-foreground">{n.node_type}</span>
                    {n.detail_path && inAppFindingLink(n.detail_path) ? (
                      <Link
                        href={inAppFindingLink(n.detail_path)!}
                        className="font-medium hover:underline"
                      >
                        {n.label}
                      </Link>
                    ) : (
                      <span className="font-medium">{n.label}</span>
                    )}
                    <span className="text-muted-foreground">· {n.open_finding_count} open</span>
                    {n.findings_list_path && (
                      <Link href={n.findings_list_path} className="text-primary underline">
                        All findings
                      </Link>
                    )}
                  </div>
                  <ul className="mt-1 space-y-1 pl-3">
                    {n.open_findings.map((f) => (
                      <li key={f.id} className="flex items-center justify-between gap-2">
                        <Link href={`/findings/${f.id}`} className="hover:underline">
                          {f.title}
                        </Link>
                        <SeverityBadge severity={f.severity} />
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
          {(finding.blast_radius!.findings ?? []).length > 0 &&
            (finding.blast_radius!.neighbors ?? []).length === 0 && (
              <ul className="space-y-2">
                {finding.blast_radius!.findings.map((f) => (
                  <li key={f.id} className="flex items-center justify-between gap-3 text-sm">
                    <div>
                      <Link href={`/findings/${f.id}`} className="font-medium hover:underline">
                        {f.title}
                      </Link>
                      <p className="text-xs text-muted-foreground">
                        {f.subject_type}
                        {f.subject_label ? ` · ${f.subject_label}` : ""}
                      </p>
                    </div>
                    <SeverityBadge severity={f.severity} />
                  </li>
                ))}
              </ul>
            )}
        </CardContent>
      </Card>
    ) : finding.blast_radius?.subject_node_id ? (
      <Card id="blast-radius">
        <CardHeader>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-eyebrow">Blast radius</span>
            <span className="flex gap-3 text-sm font-normal">
              <a
                href={`/api/findings/${id}/blast-radius/export?format=csv`}
                className="text-primary underline"
              >
                Export CSV
              </a>
              <a
                href={`/api/findings/${id}/blast-radius/export?format=json`}
                className="text-primary underline"
              >
                Export JSON
              </a>
            </span>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No open findings on graph neighbors within depth {finding.blast_radius.depth}. JSON
            export still includes the graph subgraph for incident handoff.
          </p>
        </CardContent>
      </Card>
    ) : null;

  const relatedCard = hasRelated ? (
    <Card>
      <CardHeader className="text-eyebrow">
        Related findings ({finding.related_findings.length})
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {finding.related_findings.map((f) => (
            <li key={f.id} className="flex items-center justify-between gap-3 text-sm">
              <Link href={`/findings/${f.id}`} className="min-w-0 break-words font-medium hover:underline">
                {f.title}
              </Link>
              <div className="flex shrink-0 gap-2">
                <SeverityBadge severity={f.severity} />
                <StatusBadge status={f.status} />
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  ) : null;

  const cohortCard = hasCohort ? (
    <Card>
      <CardHeader className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="flex flex-wrap items-baseline gap-2">
          <span className="text-eyebrow">Same-policy cohort</span>
          <span className="text-xs normal-case tracking-normal text-muted-foreground">
            {finding.same_policy_cohort!.open_other_count} open ·{" "}
            {finding.same_policy_cohort!.total_other_count} other
            {finding.same_policy_cohort!.policy_slug
              ? ` · ${finding.same_policy_cohort!.policy_slug}`
              : ""}
          </span>
        </span>
        {finding.same_policy_cohort!.list_path ? (
          <Link
            href={finding.same_policy_cohort!.list_path}
            className="text-sm font-normal text-primary underline"
          >
            All open for policy
          </Link>
        ) : null}
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-xs text-muted-foreground">
          Other findings for this detection across subjects (not the same-subject related list).
        </p>
        <ul className="space-y-2">
          {finding.same_policy_cohort!.items.map((f) => (
            <li key={f.id} className="flex items-center justify-between gap-3 text-sm">
              <div className="min-w-0">
                <Link href={f.detail_path} className="break-words font-medium hover:underline">
                  {f.title}
                </Link>
                <p className="text-xs text-muted-foreground">{f.subject_type}</p>
              </div>
              <div className="flex shrink-0 gap-2">
                <SeverityBadge severity={f.severity} />
                <StatusBadge status={f.status} />
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  ) : null;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <FindingDetailHeader
        finding={finding}
        findingId={id}
        subjectLabel={subjectLabel}
        jumpLinks={jumpLinks}
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,22rem)]">
        <div className="space-y-6">
          <FindingSubjectCard subject={finding.subject} />

          <FindingEvidencePanel findingId={finding.id} evidence={finding.evidence} />

          <div
            className={
              blastRadiusCard
                ? "grid gap-6 xl:grid-cols-2"
                : "grid gap-6"
            }
          >
            {attackPathCard}
            {blastRadiusCard}
          </div>

          {hasRelated || hasCohort ? (
            <div
              id="related"
              className={
                hasRelated && hasCohort ? "grid gap-6 xl:grid-cols-2" : "grid gap-6"
              }
            >
              {relatedCard}
              {cohortCard}
            </div>
          ) : null}

          <Card id="activity">
            <CardHeader className="text-eyebrow">Activity</CardHeader>
            <CardContent>
              {(finding.activity ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">No activity recorded yet.</p>
              ) : (
                <ol className="relative ml-2 space-y-0 border-l border-border">
                  {(finding.activity ?? []).map((event, idx) => (
                    <li
                      key={`${event.at}-${event.action}-${idx}`}
                      className="relative pb-4 pl-5 last:pb-0"
                    >
                      <span
                        className="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full border border-border bg-background"
                        aria-hidden
                      />
                      <p className="text-sm font-medium">{event.summary}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        <LocalTime value={event.at} />
                        {event.actor
                          ? ` · ${event.actor.display_name ?? event.actor.email}`
                          : event.kind === "detected"
                            ? " · system"
                            : ""}
                        {event.action !== "finding.detected" ? ` · ${event.action}` : ""}
                      </p>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>

          <div className="grid gap-6 xl:grid-cols-2">
            <Card id="notes">
              <CardHeader className="text-eyebrow">Investigation notes</CardHeader>
              <CardContent className="space-y-4">
                <p className="text-xs text-muted-foreground">
                  Append-only collaboration notes — distinct from exceptions, mute, and status
                  changes.
                </p>
                {(finding.notes ?? []).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No notes yet.</p>
                ) : (
                  <ul className="space-y-3 text-sm">
                    {(finding.notes ?? []).map((note) => (
                      <li key={note.id} className="rounded-md border border-border px-3 py-2">
                        <p className="whitespace-pre-wrap">{note.body}</p>
                        <p className="mt-1 text-muted-foreground">
                          {note.author?.display_name ?? note.author?.email ?? "Unknown operator"}
                          {note.created_at ? (
                            <>
                              {" · "}
                              <LocalTime value={note.created_at} />
                            </>
                          ) : null}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
                <FindingActionForm
                  action={noteAction}
                  className="flex flex-col gap-2 border-t border-border pt-4"
                >
                  <p className="text-sm font-medium">Add note</p>
                  <Textarea
                    name="body"
                    required
                    rows={3}
                    maxLength={4000}
                    aria-label="Note"
                    placeholder="Investigation progress, context for teammates, …"
                  />
                  <Button type="submit" size="sm" variant="outline" className="w-fit">
                    <NotebookPen aria-hidden />
                    Add Note
                  </Button>
                </FindingActionForm>
              </CardContent>
            </Card>

            <Card id="exceptions">
              <CardHeader className="text-eyebrow">Exceptions</CardHeader>
              <CardContent className="space-y-4">
                {finding.exceptions.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No exceptions recorded yet.</p>
                ) : (
                  <ul className="space-y-3 text-sm">
                    {finding.exceptions.map((ex) => (
                      <li key={ex.id} className="rounded-md border border-border px-3 py-2">
                        <p>{ex.reason}</p>
                        <p className="mt-1 text-muted-foreground">
                          {ex.created_by?.display_name ??
                            ex.created_by?.email ??
                            "Unknown operator"}
                          {ex.created_at ? (
                            <>
                              {" · "}
                              <LocalTime value={ex.created_at} />
                            </>
                          ) : null}
                          {ex.expires_at ? (
                            <>
                              {" · expires "}
                              <LocalTime value={ex.expires_at} />
                            </>
                          ) : (
                            " · no expiry"
                          )}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
                {(finding.control_cross_links?.controls.length ?? 0) > 0 ? (
                  <div className="space-y-3 border-t border-border pt-4">
                    <p className="text-sm font-medium">Linked compliance controls</p>
                    <p className="text-xs text-muted-foreground">
                      {finding.control_cross_links?.notes}
                    </p>
                    <ul className="space-y-3 text-sm">
                      {finding.control_cross_links?.controls.map((c) => (
                        <li key={c.id} className="rounded-md border border-border px-3 py-2">
                          <span className="font-medium">
                            {c.framework} {c.control_id}
                            {c.title ? ` — ${c.title}` : ""}
                          </span>
                          {c.open_peers.length > 0 ? (
                            <p className="mt-2 text-xs text-muted-foreground">
                              Open peers:{" "}
                              {c.open_peers.map((p, i) => (
                                <span key={p.id}>
                                  {i > 0 ? ", " : ""}
                                  <Link href={`/findings/${p.id}`} className="underline">
                                    {p.title}
                                  </Link>
                                </span>
                              ))}
                            </p>
                          ) : null}
                          {c.exception_peers.length > 0 ? (
                            <p className="mt-1 text-xs text-muted-foreground">
                              Exception peers:{" "}
                              {c.exception_peers.map((p, i) => (
                                <span key={p.id}>
                                  {i > 0 ? ", " : ""}
                                  <Link href={`/findings/${p.id}`} className="underline">
                                    {p.title}
                                  </Link>
                                </span>
                              ))}
                            </p>
                          ) : null}
                          {(c.muted_peers?.length ?? 0) > 0 ? (
                            <p className="mt-1 text-xs text-muted-foreground">
                              Muted peers:{" "}
                              {c.muted_peers?.map((p, i) => (
                                <span key={p.id}>
                                  {i > 0 ? ", " : ""}
                                  <Link href={`/findings/${p.id}`} className="underline">
                                    {p.title}
                                  </Link>
                                </span>
                              ))}
                            </p>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <FindingActionForm
                  action={exceptionAction}
                  localDateTimeFields={{ expires_at_local: "expires_at" }}
                  className="flex flex-col gap-2 border-t border-border pt-4"
                >
                  <p className="text-sm font-medium">Create exception</p>
                  <Input
                    name="reason"
                    required
                    aria-label="Exception reason"
                    placeholder="Reason (accepted risk, compensating control, …)"
                  />
                  <label className="flex flex-col gap-1 text-sm">
                    <span className="text-muted-foreground">Expires (optional, your local time)</span>
                    <Input name="expires_at_local" type="datetime-local" className="w-fit" />
                  </label>
                  <Button type="submit" size="sm" variant="outline" className="w-fit">
                    <ShieldCheck aria-hidden />
                    Create Exception
                  </Button>
                </FindingActionForm>
              </CardContent>
            </Card>
          </div>
        </div>

        <FindingActionRail
          finding={finding}
          findingId={id}
          operators={operators}
          ticketIntegrations={ticketIntegrations}
          canCreateTickets={me.role === "analyst" || me.role === "admin"}
          resolveAction={resolveAction}
          reopenAction={reopenAction}
          suppressAction={suppressAction}
          muteAction={muteAction}
          unmuteAction={unmuteAction}
          assignAction={assignAction}
          watchAction={watchAction}
          unwatchAction={unwatchAction}
        />
      </div>
    </div>
  );
}
