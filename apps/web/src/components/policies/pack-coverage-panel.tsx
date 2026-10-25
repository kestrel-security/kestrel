// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import type { ComponentType } from "react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { PackCoverage } from "@/lib/types";

/** Coverage report: which pack checks are assessable vs blocked on missing data. */
export function PackCoveragePanel({ coverage }: { coverage: PackCoverage }) {
  const monitored = coverage.policies.filter((p) => p.status === "monitored");
  const blocked = coverage.policies.filter((p) => p.status === "not_assessable");

  return (
    <div className="space-y-3 rounded-lg border border-border bg-elevated px-4 py-3">
      <div>
        <p className="text-eyebrow">Coverage</p>
        <p className="mt-1 text-sm text-muted-foreground">
          {coverage.connected
            ? `${coverage.counts.monitored} of ${coverage.counts.total} checks can assess posture from connected integration data.`
            : "Connect the integration for this application to assess pack checks."}
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <CoverageGroup
          label="Monitored"
          icon={CheckCircle2}
          tone="text-green-700 dark:text-green-300"
          items={monitored}
        />
        <CoverageGroup
          label="Not assessable"
          icon={AlertTriangle}
          tone="text-amber-800 dark:text-amber-300"
          items={blocked}
        />
      </div>
    </div>
  );
}

function CoverageGroup({
  label,
  icon: Icon,
  tone,
  items,
}: {
  label: string;
  icon: ComponentType<{ className?: string }>;
  tone: string;
  items: PackCoverage["policies"];
}) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <p className={`flex items-center gap-1.5 font-medium ${tone}`}>
        <Icon className="size-3.5 shrink-0" aria-hidden />
        {label} <span className="font-normal text-muted-foreground">({items.length})</span>
      </p>
      {items.length === 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">None.</p>
      ) : (
        <ul className="mt-1.5 max-h-48 space-y-1 overflow-y-auto text-xs">
          {items.map((p) => (
            <li key={p.slug} className="text-muted-foreground">
              <span className="font-medium text-foreground">{p.title}</span>
              <span className="ml-1 font-mono">({p.slug})</span>
              {p.reason ? <p className="mt-0.5 text-muted-foreground">{p.reason}</p> : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function PackEnableControls({
  packName,
  installed,
  enableAction,
  disableAction,
}: {
  packName: string;
  installed: boolean;
  enableAction: () => Promise<void>;
  disableAction: () => Promise<void>;
}) {
  if (!installed) return null;
  return (
    <div className="flex flex-wrap gap-2">
      <form action={enableAction}>
        <Button type="submit" size="sm" variant="outline">
          Enable all policies
        </Button>
      </form>
      <form action={disableAction}>
        <Button type="submit" size="sm" variant="outline">
          Disable all policies
        </Button>
      </form>
      <Button asChild size="sm" variant="ghost">
        <Link href={`/policies?pack=${encodeURIComponent(packName)}`}>View installed</Link>
      </Button>
    </div>
  );
}

export function PackProfileInstallLinks({
  packHref,
  installed,
}: {
  packHref: string;
  installed: boolean;
}) {
  const profiles = [
    { id: "level_1", label: "Level 1 (essential)" },
    { id: "level_2", label: "Level 2 (defense in depth)" },
    { id: "monitor", label: "Activity monitors" },
  ] as const;
  return (
    <div className="flex flex-wrap gap-2">
      <Button asChild size="sm">
        <Link href={`${packHref}?preview=1`}>{installed ? "Re-install all" : "Install all"}</Link>
      </Button>
      {profiles.map((p) => (
        <Button key={p.id} asChild size="sm" variant="outline">
          <Link href={`${packHref}?preview=1&profile=${p.id}`}>Install {p.label}</Link>
        </Button>
      ))}
    </div>
  );
}
