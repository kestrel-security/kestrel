// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { updateNotificationPreferences } from "@/lib/actions/notifications";
import type { OperatorNotificationPreferences } from "@/lib/types";

const SEVERITIES = ["low", "medium", "high", "critical"] as const;
const EVENTS = [
  { value: "finding.opened", label: "Finding opened" },
  { value: "finding.resolved", label: "Finding resolved" },
] as const;

export function NotificationPreferencesForm({ prefs }: { prefs: OperatorNotificationPreferences }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [minSeverity, setMinSeverity] = useState(prefs.min_severity);

  return (
    <form
      className="space-y-6"
      onSubmit={(e) => {
        e.preventDefault();
        const fd = new FormData(e.currentTarget);
        const muted = EVENTS.filter((ev) => fd.get(`mute_${ev.value}`) === "on").map((ev) => ev.value);
        setError(null);
        setSaved(false);
        startTransition(async () => {
          const result = await updateNotificationPreferences({
            email_enabled: fd.get("email_enabled") === "on",
            in_app_enabled: fd.get("in_app_enabled") === "on",
            findings_enabled: fd.get("findings_enabled") === "on",
            webhook_failures_enabled: fd.get("webhook_failures_enabled") === "on",
            min_severity: minSeverity,
            muted_events: muted,
          });
          if (!result.ok) {
            setError(result.error);
            return;
          }
          setSaved(true);
          router.refresh();
        });
      }}
    >
      <fieldset className="space-y-3">
        <legend className="text-sm font-medium">Delivery channels</legend>
        <label className="flex items-start gap-2 text-sm">
          <Checkbox
            name="in_app_enabled"
            defaultChecked={prefs.in_app_enabled}
            disabled={pending}
            className="mt-0.5"
          />
          <span>
            In-app
            <span className="block text-xs text-muted-foreground">
              Listed under the bell in the sidebar, with an unread count.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <Checkbox
            name="email_enabled"
            defaultChecked={prefs.email_enabled}
            disabled={pending}
            className="mt-0.5"
          />
          <span>
            Email
            <span className="block text-xs text-muted-foreground">
              {prefs.email_configured
                ? "The same events, sent to your address, plus a weekly digest of findings you watch."
                : "Saved, but nothing is sent until an administrator sets up email."}
            </span>
          </span>
        </label>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium">What to notify about</legend>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox name="findings_enabled" defaultChecked={prefs.findings_enabled} disabled={pending} />
          Findings opened or resolved anywhere in the organization
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox
            name="webhook_failures_enabled"
            defaultChecked={prefs.webhook_failures_enabled}
            disabled={pending}
          />
          Webhook delivery failures (sent to admins only)
        </label>
      </fieldset>

      <div className="max-w-xs space-y-1.5">
        <Label htmlFor="min-severity" className="flex flex-col items-start gap-0.5">
          <span>Minimum finding severity</span>
        </Label>
        <p className="text-xs text-muted-foreground">
          Only notify for findings at or above this severity. Distinct from muting a finding.
        </p>
        <Select value={minSeverity} onValueChange={setMinSeverity} disabled={pending}>
          <SelectTrigger id="min-severity" className="capitalize">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium">Mute finding event types</legend>
        {EVENTS.map((ev) => (
          <label key={ev.value} className="flex items-center gap-2 text-sm">
            <Checkbox
              name={`mute_${ev.value}`}
              defaultChecked={prefs.muted_events.includes(ev.value)}
              disabled={pending}
            />
            Mute {ev.label}
          </label>
        ))}
      </fieldset>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {saved && !error ? (
        <p className="rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-800 dark:text-green-300">
          Preferences saved.
        </p>
      ) : null}

      <Button type="submit" size="sm" disabled={pending}>
        {pending ? "Saving…" : "Save preferences"}
      </Button>
    </form>
  );
}
