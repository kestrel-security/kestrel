// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { previewWatchDigest } from "@/lib/actions/notifications";
import type { WatchDigestPreview } from "@/lib/types";
import { relativeTime } from "@/lib/utils";

const REASONS: Record<NonNullable<WatchDigestPreview["reason"]>, string> = {
  email_not_configured: "Email is not set up for this organization, so no digest is sent.",
  email_disabled: "Email is turned off in your preferences above.",
  no_email_address: "Your account has no email address.",
  no_watches: "You are not watching any findings. Open a finding and choose Watch.",
  no_changes: "Nothing you watch changed this week, so this week's digest is skipped.",
  already_sent_this_window: "This week's digest has already been sent.",
};

export function WatchDigestPreviewCard() {
  const [pending, startTransition] = useTransition();
  const [preview, setPreview] = useState<WatchDigestPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Watched findings digest</CardTitle>
        <CardDescription>
          Once a week, if anything you watch changed, Kestrel emails you a summary: what is still
          open, what was resolved, and what was active in the last 7 days.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={pending}
          onClick={() => {
            setError(null);
            startTransition(async () => {
              const result = await previewWatchDigest();
              if (result.ok) setPreview(result.data);
              else setError(result.error);
            });
          }}
        >
          {pending ? "Loading…" : preview ? "Refresh preview" : "Preview my digest"}
        </Button>

        {error ? <Callout tone="error">{error}</Callout> : null}

        {preview ? (
          <div className="space-y-3" aria-live="polite">
            {preview.would_send ? (
              <Callout tone="success">
                The next scheduled run will send this to {preview.recipient}.
              </Callout>
            ) : preview.reason ? (
              <Callout>{REASONS[preview.reason]}</Callout>
            ) : null}
            {preview.last_sent_at ? (
              <p className="text-xs text-muted-foreground">
                Last sent {relativeTime(preview.last_sent_at)}.
              </p>
            ) : null}
            <div className="rounded-md border border-border">
              <p className="border-b border-border px-3 py-2 text-sm font-medium">
                {preview.subject}
              </p>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap px-3 py-2 font-mono text-xs text-muted-foreground">
                {preview.body_text}
              </pre>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
