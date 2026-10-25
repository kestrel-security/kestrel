// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { changePassword } from "@/lib/actions/auth";
import {
  PASSWORD_POLICY_HINT,
  changePasswordProblem,
} from "@/lib/password-policy";

export function ChangePasswordForm({ email }: { email: string }) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const current = String(data.get("current_password") ?? "");
    const next = String(data.get("new_password") ?? "");
    const confirm = String(data.get("confirm_password") ?? "");
    setSaved(false);
    const problem = changePasswordProblem({ current, next, confirm });
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    startTransition(async () => {
      const result = await changePassword({ currentPassword: current, newPassword: next });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      form.reset();
      setSaved(true);
    });
  }

  return (
    <form onSubmit={onSubmit} className="max-w-md space-y-4" noValidate>
      {/* Lets password managers file the new password under the right account. */}
      <input type="hidden" name="username" autoComplete="username" value={email} readOnly />
      {error ? <Callout tone="error">{error}</Callout> : null}
      {saved ? (
        <Callout tone="success" role="status">
          Password changed. Your other sessions have been signed out; this one stays signed in.
        </Callout>
      ) : null}
      <div className="space-y-1.5">
        <Label htmlFor="current-password">Current password</Label>
        <Input
          id="current-password"
          name="current_password"
          type="password"
          required
          autoComplete="current-password"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="new-password">New password</Label>
        <Input
          id="new-password"
          name="new_password"
          type="password"
          required
          autoComplete="new-password"
          aria-describedby="new-password-hint"
        />
        <p id="new-password-hint" className="text-xs text-muted-foreground">
          {PASSWORD_POLICY_HINT}
        </p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="confirm-password">Confirm new password</Label>
        <Input
          id="confirm-password"
          name="confirm_password"
          type="password"
          required
          autoComplete="new-password"
        />
      </div>
      <Button type="submit" size="sm" disabled={pending}>
        {pending ? "Changing…" : "Change password"}
      </Button>
    </form>
  );
}
