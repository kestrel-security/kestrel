// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

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
import { rotateWebhookSecret } from "@/lib/actions/integrations";

export function RotateWebhookSecretButton({ webhookId }: { webhookId: string }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function onConfirm() {
    setError(null);
    startTransition(async () => {
      const result = await rotateWebhookSecret(webhookId);
      if (!result.ok) {
        setError(result.error);
        toast("Could not rotate the signing secret", { tone: "error", detail: result.error });
        return;
      }
      toast("Signing secret rotated", { detail: "Copy the new secret now — it is not shown again." });
      setSecret(result.signing_secret);
    });
  }

  if (secret) {
    return (
      <div className="max-w-md space-y-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2">
        <p className="text-xs font-medium text-amber-900 dark:text-amber-300">
          New signing secret — copy now
        </p>
        <code className="block break-all font-mono text-xs text-foreground">{secret}</code>
        <p className="text-[11px] text-muted-foreground">
          The previous secret no longer validates. This value will not be shown again.
        </p>
      </div>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (next) setError(null); }}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          Rotate secret
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rotate this webhook signing secret?</DialogTitle>
          <DialogDescription>
            Receivers must update to the new secret. The old secret stops working immediately.
          </DialogDescription>
        </DialogHeader>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button type="button" size="sm" onClick={onConfirm} disabled={pending}>
            {pending ? "Rotating…" : "Rotate secret"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
