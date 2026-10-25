// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";
import {
  resetOperatorMfa,
  resetOperatorPassword,
  setOperatorActive,
  setOperatorRole,
  setRequireMfa,
} from "@/lib/actions/settings";
import { PASSWORD_POLICY_HINT, generateTemporaryPassword, newPasswordProblem } from "@/lib/password-policy";
import { countOf } from "@/lib/plural";
import type { OrgSecurity } from "@/lib/types";

const ROLES = ["read_only", "analyst", "admin"] as const;

export function OperatorRoleSelect({
  operatorId,
  role,
  disabled,
}: {
  operatorId: string;
  role: string;
  disabled?: boolean;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [value, setValue] = useState(role);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="space-y-1">
      <Select
        value={value}
        disabled={disabled || pending}
        onValueChange={(next) => {
          const previous = value;
          setValue(next);
          setError(null);
          startTransition(async () => {
            const result = await setOperatorRole(operatorId, next);
            if (!result.ok) {
              setValue(previous);
              setError(result.error);
              toast("Could not change the role", { tone: "error", detail: result.error });
              return;
            }
            toast(`Role changed to ${next.replace("_", " ")}`);
            router.refresh();
          });
        }}
      >
        <SelectTrigger className="h-8 w-36 text-xs" aria-label="Operator role">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {ROLES.map((r) => (
            <SelectItem key={r} value={r} className="capitalize">
              {r.replace("_", " ")}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}

export function OperatorActiveButton({
  operatorId,
  isActive,
  email,
}: {
  operatorId: string;
  isActive: boolean;
  email: string;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function onConfirm() {
    setError(null);
    startTransition(async () => {
      const result = await setOperatorActive(operatorId, !isActive);
      if (!result.ok) {
        setError(result.error);
        toast(isActive ? "Could not deactivate the operator" : "Could not reactivate the operator", {
          tone: "error",
          detail: result.error,
        });
        return;
      }
      toast(isActive ? `Deactivated ${email}` : `Reactivated ${email}`);
      setOpen(false);
      router.refresh();
    });
  }

  if (!isActive) {
    return (
      <div className="space-y-1">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={pending}
          onClick={onConfirm}
        >
          {pending ? "Saving…" : "Reactivate"}
        </Button>
        {error ? <p className="text-xs text-destructive">{error}</p> : null}
      </div>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (next) setError(null); }}>
      <DialogTrigger asChild>
        <Button type="button" variant="destructive" size="sm">
          Deactivate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Deactivate {email}?</DialogTitle>
          <DialogDescription>
            They will no longer be able to sign in until reactivated.
          </DialogDescription>
        </DialogHeader>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" size="sm" onClick={onConfirm} disabled={pending}>
            {pending ? "Saving…" : "Deactivate"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Admin reset of another operator's password. The temporary password is shown
 * once after the reset so it can be handed over; the operator then changes it
 * at Settings → Account. Their sessions end at once (the API does that).
 */
export function OperatorResetPasswordButton({ operatorId, email }: { operatorId: string; email: string }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [revokeApiTokens, setRevokeApiTokens] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [pending, startTransition] = useTransition();

  function reset(next: boolean) {
    setOpen(next);
    if (next) {
      setPassword(generateTemporaryPassword());
      setRevokeApiTokens(true);
      setError(null);
      setDone(null);
      setCopied(false);
    }
  }

  function onConfirm() {
    const problem = newPasswordProblem(password);
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    startTransition(async () => {
      const result = await resetOperatorPassword(operatorId, { password, revokeApiTokens });
      if (!result.ok) {
        setError(result.error);
        toast("Could not reset the password", { tone: "error", detail: result.error });
        return;
      }
      toast(`Password reset for ${email}`);
      setDone(password);
    });
  }

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          Reset password
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password for {email}</DialogTitle>
          <DialogDescription>
            {done
              ? "Give them this temporary password and ask them to change it at Settings → Account. It is not shown again."
              : "Their current sessions end immediately. Share the temporary password with them; they can change it at Settings → Account."}
          </DialogDescription>
        </DialogHeader>
        {done ? (
          <div className="flex items-center gap-2">
            <Input readOnly value={done} aria-label="Temporary password" className="font-mono" />
            <Button type="button" variant="outline" size="sm" onClick={() => copy(done)}>
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor={`reset-password-${operatorId}`}>Temporary password</Label>
              <div className="flex items-center gap-2">
                <Input
                  id={`reset-password-${operatorId}`}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="font-mono"
                  autoComplete="off"
                  spellCheck={false}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setPassword(generateTemporaryPassword())}
                  disabled={pending}
                >
                  Generate
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">{PASSWORD_POLICY_HINT}</p>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={revokeApiTokens}
                onCheckedChange={(value) => setRevokeApiTokens(value === true)}
                disabled={pending}
              />
              Also revoke their API tokens
            </label>
          </div>
        )}
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          {done ? (
            <Button type="button" size="sm" onClick={() => setOpen(false)}>
              Done
            </Button>
          ) : (
            <>
              <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)} disabled={pending}>
                Cancel
              </Button>
              <Button type="button" size="sm" onClick={onConfirm} disabled={pending}>
                {pending ? "Resetting…" : "Reset password"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Admin reset of another operator's second factor, for a lost or replaced
 * phone. Their sessions end; their next sign-in is password only, or asks
 * them to set MFA up again when the organization requires it.
 */
export function OperatorResetMfaButton({ operatorId, email }: { operatorId: string; email: string }) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onConfirm() {
    setError(null);
    startTransition(async () => {
      const result = await resetOperatorMfa(operatorId);
      if (!result.ok) {
        setError(result.error);
        toast("Could not reset two-factor authentication", { tone: "error", detail: result.error });
        return;
      }
      toast(`Two-factor authentication reset for ${email}`);
      setOpen(false);
      router.refresh();
    });
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (next) setError(null); }}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          Reset MFA
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset two-factor authentication for {email}?</DialogTitle>
          <DialogDescription>
            This removes their authenticator app and recovery codes and signs them out everywhere.
            Use it when they have lost their phone. Their next sign-in needs only their password,
            or asks them to set up a new authenticator if your organization requires it.
          </DialogDescription>
        </DialogHeader>
        <div aria-live="polite" className="empty:hidden">
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" size="sm" onClick={onConfirm} disabled={pending}>
            {pending ? "Resetting…" : "Reset MFA"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** The organization-wide "every operator needs MFA" switch. */
export function RequireMfaToggle({ security }: { security: OrgSecurity }) {
  const router = useRouter();
  const { toast } = useToast();
  const [state, setState] = useState(security);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function onChange(requireMfa: boolean) {
    const previous = state;
    setState({ ...state, require_mfa: requireMfa });
    setError(null);
    startTransition(async () => {
      const result = await setRequireMfa(requireMfa);
      if (!result.ok) {
        setState(previous);
        setError(result.error);
        toast("Could not change the sign-in policy", { tone: "error", detail: result.error });
        return;
      }
      setState(result.security);
      toast(
        requireMfa
          ? "Two-factor authentication is now required"
          : "Two-factor authentication is no longer required",
      );
      router.refresh();
    });
  }

  const missing = state.active_operators_without_mfa;
  const who = `${countOf(missing, "active operator")} ${missing === 1 ? "hasn't" : "haven't"} set it up`;
  return (
    <div className="space-y-2">
      <div className="flex items-start gap-3">
        <Checkbox
          id="require-mfa"
          checked={state.require_mfa}
          onCheckedChange={(value) => onChange(value === true)}
          disabled={pending}
          aria-describedby="require-mfa-hint"
          className="mt-0.5"
        />
        <div className="space-y-1">
          <Label htmlFor="require-mfa" className="leading-snug">
            Require two-factor authentication for every operator
          </Label>
          <p id="require-mfa-hint" className="text-xs text-muted-foreground" aria-live="polite">
            {missing === 0
              ? "Every active operator has set it up."
              : state.require_mfa
                ? `${who}; they'll be asked to at their next sign-in.`
                : `${who}. Turning this on asks them to at their next sign-in; nobody is signed out.`}
          </p>
        </div>
      </div>
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}
