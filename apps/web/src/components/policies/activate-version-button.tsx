// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState } from "react";
import { History } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

/**
 * Confirm-gated Activate for custom policy version rollback.
 * Pack policies never render this — the detail page gates on can_activate.
 */
export function ActivateVersionButton({
  versionId,
  versionLabel,
  action,
}: {
  versionId: string;
  versionLabel: string;
  action: (formData: FormData) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          <History aria-hidden />
          Activate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Activate {versionLabel}?</DialogTitle>
          <DialogDescription>
            The current version pointer moves to this immutable snapshot. Evaluation uses the
            activated source immediately — including the next integration sync or manual evaluate.
            This does not delete history; you can activate any prior version again later.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <form action={action} onSubmit={() => setOpen(false)}>
            <input type="hidden" name="version_id" value={versionId} />
            <Button type="submit" size="sm">
              Activate {versionLabel}
            </Button>
          </form>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
