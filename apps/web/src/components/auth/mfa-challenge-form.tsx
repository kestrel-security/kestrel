// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRef, useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { verifyMfaCode } from "@/lib/actions/auth";

/** The second step of sign-in: a code from the authenticator, or a recovery code. */
export function MfaChallengeForm({ next }: { next: string | null }) {
  const [useRecovery, setUseRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const inputRef = useRef<HTMLInputElement>(null);

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      // Redirects on success (and to /login when the challenge is spent).
      const result = await verifyMfaCode({ code, next });
      if (!result.ok) {
        setError(result.error);
        setCode("");
        inputRef.current?.focus();
      }
    });
  }

  function toggle() {
    setUseRecovery((value) => !value);
    setCode("");
    setError(null);
    // After React re-renders the field with its new label.
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  const inputId = "mfa-code";
  return (
    <form onSubmit={onSubmit} className="space-y-4" noValidate>
      <div aria-live="polite" className="empty:hidden">
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor={inputId}>{useRecovery ? "Recovery code" : "Authentication code"}</Label>
        {useRecovery ? (
          <Input
            key="recovery"
            ref={inputRef}
            id={inputId}
            name="code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="xxxx-xxxx"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            autoFocus
            maxLength={20}
            aria-describedby="mfa-code-hint"
            aria-invalid={error ? true : undefined}
            className="font-mono tracking-wider"
          />
        ) : (
          <Input
            key="totp"
            ref={inputRef}
            id={inputId}
            name="code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^\d\s]/g, ""))}
            placeholder="123456"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 ]*"
            required
            autoFocus
            maxLength={7}
            aria-describedby="mfa-code-hint"
            aria-invalid={error ? true : undefined}
            className="font-mono text-base tracking-[0.3em]"
          />
        )}
        <p id="mfa-code-hint" className="text-xs text-muted-foreground">
          {useRecovery
            ? "One of the codes you saved when you turned on two-factor authentication. Each works once."
            : "The 6-digit code from your authenticator app."}
        </p>
      </div>
      <Button type="submit" className="w-full" disabled={pending || code.trim().length === 0}>
        {pending ? "Verifying…" : "Verify"}
      </Button>
      <div className="flex flex-col items-center gap-2 text-sm sm:flex-row sm:justify-between">
        <button
          type="button"
          onClick={toggle}
          className="text-primary underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm"
        >
          {useRecovery ? "Use your authenticator app" : "Use a recovery code instead"}
        </button>
        <Link
          href="/login"
          className="text-muted-foreground underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm"
        >
          Start over
        </Link>
      </div>
    </form>
  );
}
