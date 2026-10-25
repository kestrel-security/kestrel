// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useState, useTransition } from "react";

import { RecoveryCodesPanel } from "@/components/mfa/recovery-codes-panel";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { activateMfa, startMfaSetup } from "@/lib/actions/auth";
import { formatSecret } from "@/lib/mfa";
import type { MfaSetup } from "@/lib/types";

type Step =
  | { kind: "intro" }
  | { kind: "scan"; setup: MfaSetup }
  | { kind: "codes"; codes: string[]; continueTo: string };

/**
 * Turning on two-factor authentication, shared by /mfa/setup (required by the
 * organization) and Settings → Account: set up a secret, confirm a first
 * code, then show the recovery codes once.
 *
 * `onDone` gets where enrolment would continue to (`next`, or the dashboard).
 */
export function MfaEnrolment({
  account,
  next,
  onDone,
  onCancel,
}: {
  account?: string;
  next?: string | null;
  onDone: (continueTo: string) => void;
  onCancel?: () => void;
}) {
  const [step, setStep] = useState<Step>({ kind: "intro" });
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [finishing, setFinishing] = useState(false);

  function begin() {
    setError(null);
    startTransition(async () => {
      const result = await startMfaSetup();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setStep({ kind: "scan", setup: result.setup });
    });
  }

  return (
    <div className="space-y-4">
      <div aria-live="polite" className="empty:hidden">
        {error ? <Callout tone="error">{error}</Callout> : null}
      </div>
      {step.kind === "intro" ? (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Use an authenticator app such as 1Password, Google Authenticator, or Microsoft
            Authenticator. After your password, Kestrel will ask for the 6-digit code it shows.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" onClick={begin} disabled={pending}>
              {pending ? "Starting…" : "Set up"}
            </Button>
            {onCancel ? (
              <Button type="button" variant="outline" size="sm" onClick={onCancel} disabled={pending}>
                Cancel
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}
      {step.kind === "scan" ? (
        <ScanStep
          setup={step.setup}
          onCancel={onCancel}
          onActivated={(codes, continueTo) => setStep({ kind: "codes", codes, continueTo })}
          next={next}
        />
      ) : null}
      {step.kind === "codes" ? (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Save your recovery codes</h3>
          <RecoveryCodesPanel
            codes={step.codes}
            account={account}
            pending={finishing}
            onContinue={() => {
              setFinishing(true);
              onDone(step.continueTo);
            }}
          />
        </div>
      ) : null}
    </div>
  );
}

function ScanStep({
  setup,
  next,
  onActivated,
  onCancel,
}: {
  setup: MfaSetup;
  next?: string | null;
  onActivated: (codes: string[], continueTo: string) => void;
  onCancel?: () => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [pending, startTransition] = useTransition();
  const grouped = formatSecret(setup.secret);

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(setup.secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      const result = await activateMfa({ code, next });
      if (!result.ok) {
        setError(result.error);
        setCode("");
        return;
      }
      onActivated(result.recoveryCodes, result.continueTo);
    });
  }

  return (
    <div className="space-y-5">
      <section className="space-y-3" aria-labelledby="mfa-step-scan">
        <h3 id="mfa-step-scan" className="text-sm font-semibold">
          1. Scan this QR code with your authenticator app
        </h3>
        <OtpauthQrCode uri={setup.otpauth_uri} />
        <div className="space-y-1.5">
          <p className="text-xs text-muted-foreground" id="mfa-secret-label">
            Can&apos;t scan it? Enter this key instead:
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <code
              aria-labelledby="mfa-secret-label"
              className="select-all break-all rounded-md border border-border bg-muted/40 px-2 py-1 font-mono text-sm"
            >
              {grouped}
            </code>
            <Button type="button" variant="outline" size="sm" onClick={copySecret}>
              {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
              {copied ? "Copied" : "Copy"}
            </Button>
            <span className="sr-only" aria-live="polite">
              {copied ? "Key copied to the clipboard" : ""}
            </span>
          </div>
        </div>
      </section>
      <form onSubmit={onSubmit} className="space-y-3" noValidate aria-labelledby="mfa-step-code">
        <h3 id="mfa-step-code" className="text-sm font-semibold">
          2. Enter the 6-digit code it shows
        </h3>
        <div aria-live="polite" className="empty:hidden">
          {error ? (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="mfa-activate-code">Authentication code</Label>
          <Input
            id="mfa-activate-code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^\d\s]/g, ""))}
            placeholder="123456"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 ]*"
            maxLength={7}
            required
            aria-invalid={error ? true : undefined}
            className="max-w-40 font-mono text-base tracking-[0.3em]"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" size="sm" disabled={pending || code.trim().length === 0}>
            {pending ? "Verifying…" : "Turn on"}
          </Button>
          {onCancel ? (
            <Button type="button" variant="outline" size="sm" onClick={onCancel} disabled={pending}>
              Cancel
            </Button>
          ) : null}
        </div>
      </form>
    </div>
  );
}

/**
 * The otpauth:// URI as a QR code, drawn in the browser. The URI carries the
 * secret, so it must never go to a third-party QR service.
 */
function OtpauthQrCode({ uri }: { uri: string }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSvg(null);
    setFailed(false);
    import("qrcode")
      .then((QRCode) => QRCode.toString(uri, { type: "svg", margin: 1, errorCorrectionLevel: "M" }))
      .then((markup) => {
        if (!cancelled) setSvg(markup);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [uri]);

  if (failed) {
    return (
      <p className="text-sm text-muted-foreground">
        The QR code couldn&apos;t be drawn. Enter the key below instead.
      </p>
    );
  }
  // White behind the code in both themes: scanners need the light quiet zone.
  return (
    <div
      role="img"
      aria-label="QR code for adding Kestrel to your authenticator app"
      className="h-44 w-44 rounded-md border border-border bg-white p-2 [&_svg]:h-full [&_svg]:w-full"
      // Generated locally by the qrcode package from the URI; no user markup.
      dangerouslySetInnerHTML={svg ? { __html: svg } : undefined}
    />
  );
}
