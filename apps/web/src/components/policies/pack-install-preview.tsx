// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import type { ComponentType } from "react";
import { CirclePlus, History, RefreshCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { PackInstallPreview } from "@/lib/types";

/**
 * Shows added / updated / unchanged slugs before pack install.
 * Confirm runs the provided server action; Cancel returns to the pack detail.
 */
export function PackInstallPreviewPanel({
  preview,
  cancelHref,
  confirmAction,
}: {
  preview: PackInstallPreview;
  cancelHref: string;
  confirmAction: () => Promise<void>;
}) {
  const { counts } = preview;
  return (
    <div className="space-y-3 rounded-lg border border-border bg-elevated px-4 py-3">
      <div>
        <p className="text-eyebrow">{preview.installed ? "Re-install preview" : "Install preview"}</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Comparing on-disk <code className="rounded bg-muted px-1 font-mono">{preview.name}</code>{" "}
          v{preview.version} to this org. Confirm to apply — nothing changes until you do.
        </p>
      </div>

      <div className="grid gap-3 text-sm sm:grid-cols-3">
        <SlugGroup
          label="Added"
          icon={CirclePlus}
          tone="text-green-700 dark:text-green-300"
          count={counts.added}
          slugs={preview.added}
          empty="None — all catalog policies already exist."
        />
        <SlugGroup
          label="Updated"
          icon={RefreshCcw}
          tone="text-amber-800 dark:text-amber-300"
          count={counts.updated}
          slugs={preview.updated}
          empty="None — no source, severity, or title changes."
          hint="Source, severity, or title differs from the installed version."
        />
        <SlugGroup
          label="Unchanged"
          icon={History}
          tone="text-muted-foreground"
          count={counts.unchanged}
          slugs={preview.unchanged}
          empty="None."
        />
      </div>

      {(preview.unassessable?.length ?? 0) > 0 ? (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm">
          <p className="font-medium text-amber-900 dark:text-amber-200">
            Not assessable yet ({preview.counts.unassessable ?? preview.unassessable?.length ?? 0})
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            These checks will install but cannot report findings until connector collection or scopes
            support the required data.
          </p>
          <ul className="mt-1.5 max-h-32 space-y-0.5 overflow-y-auto font-mono text-xs text-muted-foreground">
            {(preview.unassessable ?? []).map((slug) => (
              <li key={slug}>{slug}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-2 pt-1">
        <form action={confirmAction}>
          <Button type="submit" size="sm">
            {preview.installed ? "Confirm re-install" : "Confirm install"}
          </Button>
        </form>
        <Button asChild variant="outline" size="sm">
          <Link href={cancelHref}>Cancel</Link>
        </Button>
      </div>
    </div>
  );
}

function SlugGroup({
  label,
  count,
  slugs,
  empty,
  hint,
  icon: Icon,
  tone,
}: {
  label: string;
  count: number;
  slugs: string[];
  empty: string;
  hint?: string;
  icon: ComponentType<{ className?: string }>;
  tone: string;
}) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <p className={`flex items-center gap-1.5 font-medium ${tone}`}>
        <Icon className="size-3.5 shrink-0" aria-hidden />
        {label} <span className="font-normal text-muted-foreground">({count})</span>
      </p>
      {hint ? <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p> : null}
      {slugs.length === 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">{empty}</p>
      ) : (
        <ul className="mt-1.5 max-h-40 space-y-0.5 overflow-y-auto font-mono text-xs text-muted-foreground">
          {slugs.map((slug) => (
            <li key={slug} className="truncate">
              {slug}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
