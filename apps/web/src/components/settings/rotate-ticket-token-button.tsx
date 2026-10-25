// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { rotateTicketIntegrationToken } from "@/lib/actions/integrations";

export function RotateTicketTokenButton({ integrationId }: { integrationId: string }) {
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  if (done) {
    return <p className="text-xs text-muted-foreground">Token updated</p>;
  }

  if (!open) {
    return (
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => {
          setError(null);
          setOpen(true);
        }}
      >
        Rotate token
      </Button>
    );
  }

  return (
    <form
      className="flex max-w-xs flex-col gap-1.5 rounded-md border border-border bg-muted/30 p-2"
      onSubmit={(e) => {
        e.preventDefault();
        const fd = new FormData(e.currentTarget);
        const token = String(fd.get("api_token") ?? "");
        setError(null);
        startTransition(async () => {
          const result = await rotateTicketIntegrationToken(integrationId, token);
          if (!result.ok) {
            setError(result.error);
            return;
          }
          setDone(true);
        });
      }}
    >
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
      <Input
        name="api_token"
        type="password"
        required
        minLength={8}
        autoComplete="off"
        placeholder="New API token"
        className="h-7 text-xs"
      />
      <div className="flex gap-1">
        <Button type="submit" size="sm" className="h-7 px-2 text-xs" disabled={pending}>
          {pending ? "Saving…" : "Save token"}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 px-2 text-xs"
          disabled={pending}
          onClick={() => setOpen(false)}
        >
          Cancel
        </Button>
      </div>
    </form>
  );
}
