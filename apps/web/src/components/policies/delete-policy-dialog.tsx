// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";
import { deletePolicy } from "@/lib/actions/policies";
import { countOf } from "@/lib/plural";

export type DeletePolicyTarget = {
  policyId: string;
  title: string;
  source: string;
  packName?: string | null;
  openFindingCount?: number | null;
};

/**
 * Confirmation for the permanent delete. Controlled, so a dropdown menu can
 * open it after the menu itself has closed (Radix unmounts menu content on
 * select, which would unmount a dialog rendered inside it).
 *
 * `afterDelete` is "redirect" from the detail page, whose route no longer
 * exists once the delete lands, and "refresh" from the list.
 */
export function DeletePolicyDialog({
  target,
  open,
  onOpenChange,
  afterDelete,
  trigger,
}: {
  target: DeletePolicyTarget;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  afterDelete: "redirect" | "refresh";
  trigger?: React.ReactNode;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const openCount = target.openFindingCount ?? 0;

  function onDelete() {
    setError(null);
    startTransition(async () => {
      const outcome = await deletePolicy(target.policyId);
      if (!outcome.ok) {
        setError(outcome.error);
        toast("Could not delete the policy", { tone: "error", detail: outcome.error });
        return;
      }
      onOpenChange(false);
      toast(`Deleted “${target.title}”`, {
        detail: "Its findings, evaluation history, and versions went with it.",
      });
      if (afterDelete === "redirect") router.push("/policies");
      router.refresh();
    });
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (next) setError(null);
      }}
    >
      {trigger ? <DialogTrigger asChild>{trigger}</DialogTrigger> : null}
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete policy &ldquo;{target.title}&rdquo;?</DialogTitle>
          <DialogDescription>
            This permanently removes the policy, its {countOf(openCount, "open finding")} and every
            resolved one, their notes, evidence, and exceptions, and the evaluation history. This
            cannot be undone. To stop it running but keep the history, disable it instead.
          </DialogDescription>
        </DialogHeader>
        {target.source === "pack" ? (
          <p className="text-sm text-muted-foreground">
            This policy ships with the {target.packName ? <code>{target.packName}</code> : "pack"}{" "}
            pack. Installing that pack again restores the policy; its findings do not come back.
          </p>
        ) : null}
        {error ? <p className="whitespace-pre-wrap text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" size="sm" onClick={onDelete} disabled={pending}>
            {pending ? "Deleting…" : "Delete policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** The detail page's header button: a destructive trigger plus the dialog. */
export function DeletePolicyButton({ target }: { target: DeletePolicyTarget }) {
  const [open, setOpen] = useState(false);
  return (
    <DeletePolicyDialog
      target={target}
      open={open}
      onOpenChange={setOpen}
      afterDelete="redirect"
      trigger={
        <Button type="button" variant="destructive" size="sm">
          Delete
        </Button>
      }
    />
  );
}
