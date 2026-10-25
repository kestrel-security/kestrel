// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createWebhook } from "@/lib/actions/integrations";

const EVENT_OPTIONS = [
  { value: "finding.opened", label: "Finding opened" },
  { value: "finding.resolved", label: "Finding resolved" },
] as const;

export function WebhookCreateForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);

  // onSubmit rather than <form action>: React resets a form after its action
  // runs, which wiped every field (the token included) when the server
  // rejected the input. The form is cleared only once the create succeeds.
  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setError(null);
    const events = EVENT_OPTIONS.map((e) => e.value).filter((v) => formData.get(`event_${v}`) === "on");
    startTransition(async () => {
      const result = await createWebhook({
        name: String(formData.get("name") ?? ""),
        url: String(formData.get("url") ?? ""),
        description: String(formData.get("description") ?? "") || null,
        events,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setSecret(result.signing_secret);
      form.reset();
      router.refresh();
    });
  }

  return (
    <div className="space-y-4">
      {secret ? (
        <div className="space-y-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-3">
          <p className="text-sm font-medium text-amber-900 dark:text-amber-300">
            Copy the signing secret now
          </p>
          <p className="text-sm text-muted-foreground">
            This value will not be shown again. Receivers verify{" "}
            <code className="font-mono text-xs">X-Kestrel-Signature</code>.
          </p>
          <code className="block break-all rounded-md border border-border bg-background px-3 py-2 font-mono text-sm">
            {secret}
          </code>
          <Button type="button" variant="outline" size="sm" onClick={() => setSecret(null)}>
            Add another endpoint
          </Button>
        </div>
      ) : null}

      <form onSubmit={onSubmit} className="space-y-3">
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="space-y-1.5">
          <Label htmlFor="webhook-name">Name</Label>
          <Input id="webhook-name" name="name" required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="webhook-url">HTTPS URL</Label>
          <Input
            id="webhook-url"
            name="url"
            type="url"
            required
            placeholder="https://example.com/hooks/kestrel"
            className="font-mono"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="webhook-description">Description</Label>
          <Input id="webhook-description" name="description" />
        </div>
        <fieldset className="space-y-2">
          <legend className="mb-1 text-xs text-muted-foreground">Events</legend>
          {EVENT_OPTIONS.map((opt) => (
            <label key={opt.value} className="flex items-center gap-2 text-sm">
              <Checkbox name={`event_${opt.value}`} defaultChecked />
              {opt.label} <span className="text-xs text-muted-foreground">({opt.value})</span>
            </label>
          ))}
        </fieldset>
        <Button type="submit" size="sm" disabled={pending}>
          {pending ? "Creating…" : "Create webhook"}
        </Button>
      </form>
    </div>
  );
}
