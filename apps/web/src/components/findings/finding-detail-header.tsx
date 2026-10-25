// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { CopyHandoffButton } from "@/components/findings/copy-handoff-button";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import type { FindingDetail } from "@/lib/types";

export type FindingJumpLink = {
  href: string;
  label: string;
};

export function FindingDetailHeader({
  finding,
  findingId,
  subjectLabel,
  jumpLinks,
}: {
  finding: FindingDetail;
  findingId: string;
  subjectLabel: string;
  jumpLinks: FindingJumpLink[];
}) {
  const mutedExpired = finding.muted_until ? new Date(finding.muted_until).getTime() <= Date.now() : false;
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-4">
      <p className="mb-2 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Link href="/findings" className="hover:text-foreground hover:underline">
          Findings
        </Link>
        <span aria-hidden>/</span>
        <span className="truncate text-foreground/80">{finding.title}</span>
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">{finding.title}</h1>
        <SeverityBadge severity={finding.severity} />
        <StatusBadge status={finding.status} />
      </div>
      <p className="mt-1.5 text-sm text-muted-foreground">
        {subjectLabel}
        {finding.subject.context?.application_display_name
          ? ` · ${String(finding.subject.context.application_display_name)}`
          : ""}
        {" · "}
        First seen <LocalTime value={finding.first_seen_at} /> · Last seen{" "}
        <LocalTime value={finding.last_seen_at} />
        {finding.resolved_at ? (
          <>
            {" · Resolved "}
            <LocalTime value={finding.resolved_at} />
          </>
        ) : null}
        {finding.status === "muted" && finding.muted_until ? (
          <>
            {" · Muted until "}
            <LocalTime value={finding.muted_until} />
            {mutedExpired ? " (expired)" : null}
          </>
        ) : null}
      </p>
      <div className="mt-3">
        <CopyHandoffButton findingId={findingId} />
      </div>
      {jumpLinks.length > 0 ? (
        <nav
          aria-label="On this page"
          className="mt-4 flex flex-wrap gap-x-1 gap-y-1 border-t border-border pt-3 text-xs"
        >
          {jumpLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="rounded-md px-2 py-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              {link.label}
            </a>
          ))}
        </nav>
      ) : null}
    </div>
  );
}
