// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { MfaEnrolment } from "@/components/mfa/mfa-enrolment";
import { RecoveryCodesPanel } from "@/components/mfa/recovery-codes-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LocalTime } from "@/components/ui/local-time";
import { useToast } from "@/components/ui/toast";
import { disableMfa, regenerateRecoveryCodes } from "@/lib/actions/auth";
import { plural } from "@/lib/plural";
import type { MfaStatus } from "@/lib/types";

/** The body of Settings → Account's "Two-factor authentication" card. */
export function MfaSettings({ status, email }: { status: MfaStatus; email: string }) {
  const router = useRouter();
  const { toast } = useToast();
  // Kept up while the recovery codes are on screen, even after the refresh
  // that activation triggers reports MFA as on.
  const [enrolling, setEnrolling] = useState(false);

  if (enrolling || !status.enabled) {
    return enrolling ? (
      <div className="max-w-md">
        <MfaEnrolment
          account={email}
          onCancel={() => setEnrolling(false)}
          onDone={() => {
            setEnrolling(false);
            toast("Two-factor authentication is on");
            router.refresh();
          }}
        />
      </div>
    ) : (
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Badge variant="outline">Off</Badge>
          <span className="text-sm text-muted-foreground">
            Only your password protects this account.
          </span>
        </div>
        {status.required_by_org ? (
          <Callout tone="warning">
            Your organization requires two-factor authentication. You&apos;ll be asked to set it up
            at your next sign-in.
          </Callout>
        ) : null}
        <Button type="button" size="sm" onClick={() => setEnrolling(true)}>
          Set up two-factor authentication
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground">Status</dt>
        <dd className="flex flex-wrap items-center gap-2">
          <Badge>On</Badge>
          {status.enabled_at ? (
            <span className="text-muted-foreground">
              since <LocalTime value={status.enabled_at} format="date" />
            </span>
          ) : null}
        </dd>
        <dt className="text-muted-foreground">Recovery codes</dt>
        <dd className={status.recovery_codes_remaining <= 2 ? "text-destructive" : undefined}>
          {status.recovery_codes_remaining} {plural(status.recovery_codes_remaining, "code")} left
          {status.recovery_codes_remaining <= 2 ? ". Generate new ones soon." : ""}
        </dd>
      </dl>
      <div className="flex flex-wrap gap-2">
        <RegenerateRecoveryCodesButton email={email} />
        {status.required_by_org ? null : <TurnOffMfaButton email={email} />}
      </div>
      {status.required_by_org ? (
        <p className="text-xs text-muted-foreground">
          Your organization requires two-factor authentication, so it can&apos;t be turned off. If you
          lose your authenticator, use a recovery code or ask an administrator to reset it.
        </p>
      ) : null}
    </div>
  );
}

function CodeField({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>Authentication code</Label>
      <Input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="123456"
        inputMode="numeric"
        autoComplete="one-time-code"
        spellCheck={false}
        required
        maxLength={20}
        aria-describedby={`${id}-hint`}
        className="max-w-48 font-mono"
      />
      <p id={`${id}-hint`} className="text-xs text-muted-foreground">
        From your authenticator app, or one of your recovery codes.
      </p>
    </div>
  );
}

function RegenerateRecoveryCodesButton({ email }: { email: string }) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onOpenChange(next: boolean) {
    // Once new codes are on screen, close only through the saved checkbox.
    if (!next && codes) return;
    setOpen(next);
    if (next) {
      setCode("");
      setCodes(null);
      setError(null);
    }
  }

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      const result = await regenerateRecoveryCodes({ code });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setCodes(result.recoveryCodes);
      toast("New recovery codes generated");
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          Regenerate recovery codes
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{codes ? "Your new recovery codes" : "Regenerate recovery codes"}</DialogTitle>
          <DialogDescription>
            {codes
              ? "Your old codes no longer work."
              : "This replaces all your recovery codes, used or not. Confirm with a current code."}
          </DialogDescription>
        </DialogHeader>
        {codes ? (
          <RecoveryCodesPanel
            codes={codes}
            account={email}
            continueLabel="Done"
            onContinue={() => {
              setCodes(null);
              setOpen(false);
              router.refresh();
            }}
          />
        ) : (
          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            <CodeField id="regenerate-code" value={code} onChange={setCode} />
            <div aria-live="polite" className="empty:hidden">
              {error ? (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              ) : null}
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setOpen(false)}
                disabled={pending}
              >
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={pending || code.trim().length === 0}>
                {pending ? "Generating…" : "Generate new codes"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function TurnOffMfaButton({ email }: { email: string }) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) {
      setPassword("");
      setCode("");
      setError(null);
    }
  }

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      const result = await disableMfa({ password, code });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      toast("Two-factor authentication is off");
      setOpen(false);
      router.refresh();
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button type="button" variant="destructive" size="sm">
          Turn off
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Turn off two-factor authentication?</DialogTitle>
          <DialogDescription>
            Signing in will need only your password. Your authenticator entry and recovery codes stop
            working.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <input type="hidden" name="username" autoComplete="username" value={email} readOnly />
          <div className="space-y-1.5">
            <Label htmlFor="disable-mfa-password">Password</Label>
            <Input
              id="disable-mfa-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>
          <CodeField id="disable-mfa-code" value={code} onChange={setCode} />
          <div aria-live="polite" className="empty:hidden">
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setOpen(false)}
              disabled={pending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              size="sm"
              disabled={pending || !password || code.trim().length === 0}
            >
              {pending ? "Turning off…" : "Turn off"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
