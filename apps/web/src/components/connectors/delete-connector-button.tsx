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
import { deleteConnectorInstance } from "@/lib/actions/connectors";

export function DeleteConnectorButton({
  connectorInstanceId,
  displayName,
}: {
  connectorInstanceId: string;
  displayName: string;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function onDelete() {
    setError(null);
    startTransition(async () => {
      const outcome = await deleteConnectorInstance(connectorInstanceId);
      if (!outcome.ok) {
        setError(outcome.error);
        toast("Could not delete the integration", { tone: "error", detail: outcome.error });
        return;
      }
      setOpen(false);
      // The page navigates away, so the toast is the only record that the
      // delete succeeded rather than silently doing nothing.
      toast(`Deleted “${displayName}”`, { detail: "Its inventory, findings, and change history went with it." });
      router.push("/connectors");
      router.refresh();
    });
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) setError(null);
      }}
    >
      <DialogTrigger asChild>
        <Button type="button" variant="destructive" size="sm">
          Delete integration
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete integration &ldquo;{displayName}&rdquo;?</DialogTitle>
          <DialogDescription>
            This removes the integration, its encrypted secrets, sync history, and collected
            inventory (identities, grants, findings for this app). This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        {error ? <p className="whitespace-pre-wrap text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" size="sm" onClick={onDelete} disabled={pending}>
            {pending ? "Deleting…" : "Delete integration"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
