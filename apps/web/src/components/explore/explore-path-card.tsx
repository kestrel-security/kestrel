// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { AppMark } from "@/components/brand/app-mark";
import { Badge } from "@/components/ui/badge";
import { resolveAppMarkFromNode } from "@/lib/app-mark";
import type { GraphPathHop, GraphReachabilityPath } from "@/lib/types";
import { countOf } from "@/lib/plural";

const ACCESS_PATH_STYLES: Record<string, string> = {
  direct: "border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/50 dark:text-red-200",
  inherited_group:
    "border-slate-300 bg-slate-50 text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200",
  inherited_role:
    "border-slate-300 bg-slate-50 text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200",
  oauth_derived:
    "border-dashed border-fuchsia-400 bg-fuchsia-50 text-fuchsia-950 dark:border-fuchsia-700 dark:bg-fuchsia-950/40 dark:text-fuchsia-100",
  federated:
    "border-indigo-300 bg-indigo-50 text-indigo-900 dark:border-indigo-800 dark:bg-indigo-950/40 dark:text-indigo-200",
};

const NODE_TYPE_TONES: Record<string, string> = {
  identity: "bg-sky-100 text-sky-900 dark:bg-sky-950 dark:text-sky-200",
  group: "bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200",
  role: "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200",
  resource: "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200",
  oauth_application: "bg-fuchsia-100 text-fuchsia-900 dark:bg-fuchsia-950 dark:text-fuchsia-200",
  permission: "bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
  application: "bg-indigo-100 text-indigo-900 dark:bg-indigo-950 dark:text-indigo-200",
  setting: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300",
};

function accessLabel(path: string | null | undefined): string {
  if (!path) return "unspecified";
  return path.replace(/_/g, " ");
}

function exploreHref(objectId: string, nodeType: string, direction: "out" | "in"): string {
  const params = new URLSearchParams({
    focus: objectId,
    focus_type: nodeType,
    direction,
  });
  return `/explore?${params.toString()}`;
}

function HopChip({ hop }: { hop: GraphPathHop }) {
  const style =
    ACCESS_PATH_STYLES[hop.access_path ?? ""] ??
    "border-border bg-muted text-foreground";
  const permission =
    typeof hop.properties?.permission_level === "string"
      ? hop.properties.permission_level
      : null;
  const membership =
    typeof hop.properties?.membership_role === "string"
      ? hop.properties.membership_role
      : null;
  const detail = permission || membership;
  const appMark = resolveAppMarkFromNode({
    nodeType: hop.to.node_type,
    label: hop.to.label,
    properties: hop.to.properties,
  });
  return (
    <div
      className={`inline-flex max-w-full flex-col gap-0.5 rounded-md border px-2.5 py-1.5 text-xs ${style}`}
      title={hop.explanation}
    >
      <span className="flex min-w-0 items-center gap-1.5 font-medium">
        <AppMark mark={appMark} size={12} className="shrink-0" />
        <span className="truncate">{hop.to.label}</span>
      </span>
      <span className="text-[11px] opacity-80">
        {hop.edge_type.replace(/_/g, " ")}
        {hop.access_path ? ` · ${accessLabel(hop.access_path)}` : ""}
        {detail ? ` · ${detail}` : ""}
      </span>
    </div>
  );
}

export function ExplorePathCard({
  path,
  startLabel,
  direction,
}: {
  path: GraphReachabilityPath;
  startLabel: string;
  direction: "out" | "in";
}) {
  const dest = path.destination;
  const flipDirection: "out" | "in" = direction === "out" ? "in" : "out";

  return (
    <article className="rounded-lg border border-border bg-elevated p-4 text-elevated-foreground shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <AppMark
              mark={resolveAppMarkFromNode({
                nodeType: dest.node_type,
                label: dest.label,
                properties: dest.properties,
              })}
              size={16}
            />
            <Badge className={NODE_TYPE_TONES[dest.node_type] ?? NODE_TYPE_TONES.setting}>
              {dest.node_type.replace(/_/g, " ")}
            </Badge>
            {path.primary_access_path && (
              <Badge
                className={
                  ACCESS_PATH_STYLES[path.primary_access_path] ??
                  "bg-muted text-foreground"
                }
              >
                {accessLabel(path.primary_access_path)}
              </Badge>
            )}
          </div>
          <h3 className="mt-2 truncate text-base font-semibold">{dest.label}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {countOf(path.hop_count, "hop")} from {startLabel}
          </p>
        </div>
        <Link
          href={exploreHref(dest.object_id, dest.node_type, flipDirection)}
          className="shrink-0 text-sm text-primary underline-offset-2 hover:underline"
        >
          Explore from here
        </Link>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="rounded-md border border-border bg-muted/60 px-2.5 py-1.5 text-xs font-medium">
          {startLabel}
        </span>
        {path.hops.map((hop) => (
          <div key={`${hop.edge_id}-${hop.to.id}`} className="flex items-center gap-2">
            <span className="text-muted-foreground" aria-hidden>
              →
            </span>
            <HopChip hop={hop} />
          </div>
        ))}
      </div>

      {path.hops.length > 0 && (
        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
          {path.hops[path.hops.length - 1]?.explanation}
        </p>
      )}
    </article>
  );
}
