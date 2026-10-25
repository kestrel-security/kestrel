// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition, type FormEvent } from "react";

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
import { clearEmailSettings, saveEmailSettings } from "@/lib/actions/settings";
import { EMAIL_SECURITY_OPTIONS, defaultEmailPort, emailPasswordMustBeReentered } from "@/lib/email-settings";
import type { EmailSecurity, EmailSettings } from "@/lib/types";

export function EmailSettingsForm({ initial }: { initial: EmailSettings }) {
  const router = useRouter();
  const saved = initial.org;
  const initialSecurity: EmailSecurity = saved?.security ?? "starttls";
  const [host, setHost] = useState(saved?.host ?? "");
  const [security, setSecurity] = useState<EmailSecurity>(initialSecurity);
  const [port, setPort] = useState(String(saved?.port ?? defaultEmailPort(initialSecurity)));
  // A saved non-default port counts as edited, so switching mode keeps it.
  const [portEdited, setPortEdited] = useState(
    saved ? saved.port !== defaultEmailPort(saved.security) : false,
  );
  const [username, setUsername] = useState(saved?.username ?? "");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState(saved?.from_address ?? "");
  const [enabled, setEnabled] = useState(saved ? saved.is_enabled : true);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [clearOpen, setClearOpen] = useState(false);
  const credentialsAllowed = security !== "none";
  const passwordMustBeReentered =
    credentialsAllowed && emailPasswordMustBeReentered(saved, { host, port, username });

  function onSecurityChange(next: string) {
    const mode = next as EmailSecurity;
    setSecurity(mode);
    if (!portEdited) setPort(String(defaultEmailPort(mode)));
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNote(null);
    const portNumber = Number(port);
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      setError("Port must be a whole number from 1 to 65535.");
      return;
    }
    startTransition(async () => {
      const outcome = await saveEmailSettings({
        host: host.trim(),
        port: portNumber,
        security,
        username: credentialsAllowed ? username.trim() || null : null,
        password: credentialsAllowed ? password || null : null,
        from_address: fromAddress.trim(),
        is_enabled: enabled,
      });
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setPassword("");
      setNote(
        outcome.result.source === "org"
          ? `Saved. Email now goes through ${outcome.result.host}:${outcome.result.port}. Send a test email to check it.`
          : "Saved. These settings are disabled, so they are not used to send email.",
      );
      router.refresh();
    });
  }

  function onClear() {
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await clearEmailSettings();
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setClearOpen(false);
      setNote(outcome.cleared ? "Cleared the saved mail server." : "No mail server was saved.");
      setPassword("");
      router.refresh();
    });
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {error && <p className="text-sm text-destructive">{error}</p>}
      {note && (
        <p className="rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-800 dark:text-green-300">
          {note}
        </p>
      )}

      <p className="text-sm text-muted-foreground">
        {initial.source === "org" ? (
          <>
            Status: <span className="font-medium text-foreground">configured in Kestrel</span>
            {saved?.password_configured ? " · password on file" : ""}
          </>
        ) : initial.source === "environment" ? (
          <>
            Email currently uses the server&apos;s environment configuration (
            <span className="font-mono text-foreground">
              {initial.host}:{initial.port}
            </span>
            ). Saving here overrides it for this organization; clearing returns to it.
          </>
        ) : (
          <>
            Status: <span className="font-medium text-foreground">not configured</span> — no
            email is sent until a mail server is saved here.
          </>
        )}
        {saved && !saved.is_enabled ? " The saved settings below are disabled." : ""}
      </p>

      <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
        <div className="space-y-1">
          <Label htmlFor="email-host">SMTP host</Label>
          <Input
            id="email-host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="smtp.example.com"
            autoComplete="off"
            className="font-mono"
            required
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="email-port">Port</Label>
          <Input
            id="email-port"
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => {
              setPort(e.target.value);
              setPortEdited(true);
            }}
            className="font-mono"
            required
          />
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="email-security">Security</Label>
        <Select value={security} onValueChange={onSecurityChange}>
          <SelectTrigger id="email-security">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {EMAIL_SECURITY_OPTIONS.map((option) => (
              <SelectItem key={option.id} value={option.id}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {!credentialsAllowed && (
          <span className="block text-xs text-muted-foreground">
            Mail is sent unencrypted. A username and password need STARTTLS or SSL/TLS.
          </span>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="email-username">Username (optional)</Label>
          <Input
            id="email-username"
            value={credentialsAllowed ? username : ""}
            onChange={(e) => setUsername(e.target.value)}
            disabled={!credentialsAllowed}
            autoComplete="off"
            className="font-mono"
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="email-password">Password</Label>
          <Input
            id="email-password"
            type="password"
            value={credentialsAllowed ? password : ""}
            onChange={(e) => setPassword(e.target.value)}
            disabled={!credentialsAllowed}
            placeholder={
              saved?.password_configured && credentialsAllowed
                ? "Leave blank to keep the saved password"
                : ""
            }
            autoComplete="new-password"
            className="font-mono"
          />
        </div>
      </div>
      <span className="block text-xs text-muted-foreground">
        The password is encrypted at rest with the org master key and never returned by the API
        after save.
      </span>
      {passwordMustBeReentered && (
        <span className="block text-xs text-amber-700 dark:text-amber-300">
          Changing the host, port or username requires re-entering the password: the stored
          password is never sent to a different server or account.
        </span>
      )}

      <div className="space-y-1">
        <Label htmlFor="email-from">From address</Label>
        <Input
          id="email-from"
          type="email"
          value={fromAddress}
          onChange={(e) => setFromAddress(e.target.value)}
          placeholder="kestrel@example.com"
          required
        />
        <span className="block text-xs text-muted-foreground">
          The sender on every email Kestrel sends. Your mail server may require an address it is
          allowed to send as.
        </span>
      </div>

      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={enabled} onCheckedChange={(checked) => setEnabled(checked === true)} />
        Use this mail server for this organization&apos;s email
      </label>

      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={pending}>
          Save
        </Button>
        {saved && (
          <Dialog open={clearOpen} onOpenChange={(next) => { setClearOpen(next); if (next) setError(null); }}>
            <DialogTrigger asChild>
              <Button type="button" variant="outline" size="sm" disabled={pending}>
                Clear
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Remove the saved mail server?</DialogTitle>
                <DialogDescription>
                  Email falls back to the server&apos;s environment configuration if one is set;
                  otherwise no email is sent.
                </DialogDescription>
              </DialogHeader>
              {error ? <p className="text-sm text-destructive">{error}</p> : null}
              <DialogFooter>
                <Button type="button" variant="outline" size="sm" onClick={() => setClearOpen(false)} disabled={pending}>
                  Cancel
                </Button>
                <Button type="button" variant="destructive" size="sm" onClick={onClear} disabled={pending}>
                  {pending ? "Clearing…" : "Clear"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </form>
  );
}
