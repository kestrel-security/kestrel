// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useId, useState } from "react";
import {
  ArrowDownCircle,
  ArrowUpCircle,
  ChevronRight,
  Circle,
  Globe,
  KeyRound,
  Lock,
  PlugZap,
  ShieldOff,
  SlidersHorizontal,
  Unlock,
  Unplug,
  UserMinus,
  UserPlus,
  UserX,
  UserRoundCheck,
  type LucideIcon,
} from "lucide-react";

import { SeverityBadge } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  changeDelta,
  formatChangeValue,
  isEmptyChangeValue,
  type ChangeDelta,
} from "@/lib/change-delta";
import { cn, absoluteTime } from "@/lib/utils";
import type { ChangeSignificance, ClassifiedChange } from "@/lib/types";

/** Icon + direction per `ChangeClass` value — significance already carries severity, so
 *  this only needs to distinguish "opened up" vs "closed down" vs "drifted", never color. */
const CLASS_ICONS: Record<string, LucideIcon> = {
  admin_granted: KeyRound,
  admin_revoked: Lock,
  privilege_escalated: ArrowUpCircle,
  privilege_reduced: ArrowDownCircle,
  access_granted: Unlock,
  access_revoked: Lock,
  group_member_added: UserPlus,
  group_member_removed: UserMinus,
  oauth_app_installed: PlugZap,
  oauth_app_revoked: Unplug,
  oauth_scope_expanded: ArrowUpCircle,
  external_sharing_enabled: Globe,
  mfa_disabled: ShieldOff,
  identity_disabled: UserX,
  identity_added: UserPlus,
  identity_removed: UserMinus,
  config_drift: SlidersHorizontal,
  other: Circle,
};

function classIcon(changeClass: string): LucideIcon {
  return CLASS_ICONS[changeClass] ?? Circle;
}

function classLabel(changeClass: string): string {
  return changeClass.replace(/_/g, " ");
}

/** Relies on a `TooltipProvider` from an ancestor (the changes table wraps one) rather than
 *  mounting its own per row. */
function Timestamp({ iso }: { iso: string | null }) {
  const absolute = absoluteTime(iso);
  if (!absolute) return <span>—</span>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="tabular-nums" tabIndex={0}>
          <LocalTime value={iso} format="relative" />
        </span>
      </TooltipTrigger>
      <TooltipContent side="left">{absolute}</TooltipContent>
    </Tooltip>
  );
}

/** A single before/after evidence line, git-diff styled without relying on color alone. */
function DiffLine({
  field,
  before,
  after,
}: {
  field?: string;
  before: unknown;
  after: unknown;
}) {
  const beforeText = formatChangeValue(before);
  const afterText = formatChangeValue(after);
  // A field going from unset to a value is different from the entity itself not
  // having existed, and the `field` header is what tells the two apart.
  const absentBefore = field ? "not set" : "did not exist";
  const absentAfter = field ? "not set" : "no longer exists";
  return (
    <div className="grid gap-1 rounded-md border border-border/60 bg-background/60 font-mono text-xs">
      {field ? (
        <div className="border-b border-border/60 px-2.5 pt-1.5 text-[11px] text-muted-foreground">
          {field}
        </div>
      ) : null}
      <div className="flex items-start gap-2 px-2.5 py-1 text-destructive">
        <span aria-hidden className="select-none">
          &minus;
        </span>
        {beforeText === null ? (
          <span className="italic text-muted-foreground">{absentBefore}</span>
        ) : (
          <span className="break-all">{beforeText}</span>
        )}
      </div>
      <div className="flex items-start gap-2 px-2.5 pb-1.5 py-1 text-tone-success">
        <span aria-hidden className="select-none">
          +
        </span>
        {afterText === null ? (
          <span className="italic text-muted-foreground">{absentAfter}</span>
        ) : (
          <span className="break-all">{afterText}</span>
        )}
      </div>
    </div>
  );
}

/** The `Before → after` cell. One-sided changes render as an addition or a
 *  removal — a grant never had a prior value to arrow away from. The +/− glyph
 *  carries the direction so the tint is never the only signal. */
function ChangeDeltaCell({ delta }: { delta: ChangeDelta }) {
  if (delta.kind === "unrecorded") {
    return <span className="text-xs italic text-muted-foreground">value not recorded</span>;
  }

  if (delta.kind === "modified") {
    return (
      <span className="font-mono text-xs">
        <span className="text-destructive">{delta.before}</span>
        <span className="mx-1 text-muted-foreground" aria-hidden>
          &rarr;
        </span>
        <span className="sr-only"> changed to </span>
        <span className="text-tone-success">{delta.after}</span>
      </span>
    );
  }

  const added = delta.kind === "added";
  return (
    <span
      className={cn(
        "inline-flex items-baseline gap-1.5 rounded-md border px-1.5 py-0.5 font-mono text-xs",
        added
          ? "border-tone-success/30 bg-tone-success/10"
          : "border-destructive/30 bg-destructive/10",
      )}
    >
      <span
        aria-hidden
        className={cn("select-none font-semibold", added ? "text-tone-success" : "text-destructive")}
      >
        {added ? "+" : "\u2212"}
      </span>
      <span className="sr-only">{added ? "added " : "removed "}</span>
      <span className="break-all text-foreground">{delta.value}</span>
    </span>
  );
}

const SIGNIFICANCE_ROW_ACCENT: Record<ChangeSignificance, string> = {
  high: "border-l-4 border-l-destructive",
  medium: "border-l-4 border-l-amber-500/70",
  low: "border-l-4 border-l-transparent",
};

export function ChangeRow({ change }: { change: ClassifiedChange }) {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();
  const hasEvidence =
    !isEmptyChangeValue(change.before) ||
    !isEmptyChangeValue(change.after) ||
    change.field_changes.length > 0;
  const ClassIcon = classIcon(change.change_class);
  const multiField = change.field_changes.length > 1;
  const delta = changeDelta(change);

  function toggle() {
    if (hasEvidence) setExpanded((open) => !open);
  }

  return (
    <>
      <tr
        className={cn(
          "border-b border-border last:border-0",
          SIGNIFICANCE_ROW_ACCENT[change.significance],
          hasEvidence && "cursor-pointer hover:bg-muted/40",
        )}
        onClick={hasEvidence ? toggle : undefined}
      >
        <td className="px-4 py-3">
          <div className="font-medium leading-snug">
            {change.detail_path ? (
              <Link
                href={change.detail_path}
                className="hover:underline"
                onClick={(event) => event.stopPropagation()}
              >
                {change.summary}
              </Link>
            ) : (
              change.summary
            )}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
            {change.application_display_name ? (
              <span className="font-medium text-foreground/80">
                {change.application_display_name}
              </span>
            ) : null}
            <span>
              {change.application_display_name ? (
                <span aria-hidden className="mr-1.5">
                  ·
                </span>
              ) : null}
              {change.entity_type.replace(/_/g, " ")}
            </span>
          </div>
          {change.actor_email || change.actor_provider_id ? (
            <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
              <UserRoundCheck className="size-3 shrink-0" aria-hidden />
              <span>
                by{" "}
                <span className="font-medium text-foreground/80">
                  {change.actor_email ?? change.actor_provider_id}
                </span>
                {change.actor_occurred_at ? (
                  <>
                    {" "}
                    at <Timestamp iso={change.actor_occurred_at} />
                  </>
                ) : null}
                {change.actor_action ? (
                  <span className="ml-1 font-mono text-[11px]">({change.actor_action})</span>
                ) : null}
              </span>
            </div>
          ) : null}
        </td>
        <td className="px-4 py-3">
          <div className="flex flex-col items-start gap-1.5">
            <SeverityBadge severity={change.significance} />
            <span
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-xs font-medium capitalize text-muted-foreground"
              title={classLabel(change.change_class)}
            >
              <ClassIcon className="size-3" aria-hidden />
              {classLabel(change.change_class)}
            </span>
          </div>
        </td>
        <td className="px-4 py-3 text-muted-foreground">
          <div className="flex items-start gap-2">
            {multiField ? (
              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                {change.field_changes.length} fields changed
              </span>
            ) : (
              <ChangeDeltaCell delta={delta} />
            )}
            {hasEvidence ? (
              <button
                type="button"
                aria-expanded={expanded}
                aria-controls={panelId}
                aria-label={expanded ? "Collapse evidence" : "Expand evidence"}
                className="ml-auto shrink-0 rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={(event) => {
                  event.stopPropagation();
                  toggle();
                }}
              >
                <ChevronRight
                  className={cn(
                    "size-4 transition-transform duration-150 motion-reduce:transition-none",
                    expanded && "rotate-90",
                  )}
                />
              </button>
            ) : null}
          </div>
        </td>
        <td className="px-4 py-3 tabular-nums text-muted-foreground">
          <Timestamp iso={change.detected_at} />
        </td>
      </tr>
      {expanded && hasEvidence ? (
        <tr id={panelId} className="border-b border-border">
          <td colSpan={4} className="px-4 pb-4 pt-0">
            <div className="surface-elevated rounded-md border border-border p-4 text-sm">
              {change.field_changes.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-eyebrow">
                    {change.field_changes.length === 1 ? "Field change" : "Field changes"}
                  </p>
                  <div className="space-y-2">
                    {change.field_changes.map((fc, index) => (
                      <DiffLine
                        key={`${fc.field ?? "field"}-${index}`}
                        field={fc.field}
                        before={fc.old}
                        after={fc.new}
                      />
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-eyebrow">Evidence</p>
                  <DiffLine before={change.before} after={change.after} />
                </div>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/60 pt-3 text-xs text-muted-foreground">
                {change.application_display_name ? <span>{change.application_display_name}</span> : null}
                <span>
                  detected <LocalTime value={change.detected_at} />
                </span>
                {change.actor_email || change.actor_provider_id ? (
                  <span>
                    audit: {change.actor_email ?? change.actor_provider_id}
                    {change.actor_action ? ` · ${change.actor_action}` : ""}
                    {change.actor_occurred_at ? (
                      <>
                        {" · "}
                        <LocalTime value={change.actor_occurred_at} />
                      </>
                    ) : null}
                  </span>
                ) : null}
                {change.detail_path ? (
                  <Link
                    href={change.detail_path}
                    className="text-primary hover:underline"
                    onClick={(event) => event.stopPropagation()}
                  >
                    Open in Explore
                  </Link>
                ) : null}
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
