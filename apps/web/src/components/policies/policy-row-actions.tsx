// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { MoreHorizontal } from "lucide-react";

import { DeletePolicyDialog } from "@/components/policies/delete-policy-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/components/ui/toast";
import { togglePolicyEnabled } from "@/lib/actions/policies";

/**
 * Per-row menu on the policies list: enable/disable and delete without
 * opening the policy. System policies get no menu — they can be disabled
 * from their detail page and never deleted.
 */
export function PolicyRowActions({
  policyId,
  title,
  source,
  packName,
  isEnabled,
  openFindingCount,
}: {
  policyId: string;
  title: string;
  source: string;
  packName?: string | null;
  isEnabled: boolean | null | undefined;
  openFindingCount?: number | null;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  if (source === "system") return null;

  function onToggle() {
    const next = !isEnabled;
    startTransition(async () => {
      const result = await togglePolicyEnabled(policyId, next);
      if (!result.ok) {
        toast(next ? "Could not enable the policy" : "Could not disable the policy", {
          tone: "error",
          detail: result.error,
        });
        return;
      }
      toast(next ? `Enabled “${title}”` : `Disabled “${title}”`, {
        detail: next ? undefined : "Its open findings were resolved.",
      });
      router.refresh();
    });
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8"
            aria-label={`Actions for ${title}`}
            disabled={pending}
          >
            <MoreHorizontal aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {isEnabled != null ? (
            <DropdownMenuItem onSelect={onToggle}>{isEnabled ? "Disable" : "Enable"}</DropdownMenuItem>
          ) : null}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="text-destructive focus:text-destructive"
            onSelect={() => setConfirmOpen(true)}
          >
            Delete…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <DeletePolicyDialog
        target={{ policyId, title, source, packName, openFindingCount }}
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        afterDelete="refresh"
      />
    </>
  );
}
