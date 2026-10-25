// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { CheckCircle2, XCircle } from "lucide-react";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { sendTestEmail } from "@/lib/actions/settings";

export function SendTestEmailButton({ configured }: { configured: boolean }) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [ok, setOk] = useState<boolean | null>(null);

  function onClick() {
    setMessage(null);
    setOk(null);
    startTransition(async () => {
      const outcome = await sendTestEmail();
      if (!outcome.ok) {
        setOk(false);
        setMessage(outcome.error);
        return;
      }
      setOk(outcome.result.ok);
      setMessage(
        outcome.result.ok
          ? outcome.result.to
            ? `Sent to ${outcome.result.to}.`
            : "Sent."
          : (outcome.result.detail ?? "The test email could not be sent."),
      );
    });
  }

  return (
    <div className="space-y-2">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onClick}
        disabled={pending || !configured}
      >
        {pending ? "Sending…" : "Send test email"}
      </Button>
      {!configured && (
        <p className="text-xs text-muted-foreground">Save a mail server above to send a test.</p>
      )}
      {message && (
        <p
          className={`flex items-start gap-1.5 text-sm ${
            ok ? "text-green-800 dark:text-green-400" : "text-destructive"
          }`}
        >
          {ok ? (
            <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          ) : (
            <XCircle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          )}
          <span>{message}</span>
        </p>
      )}
    </div>
  );
}
