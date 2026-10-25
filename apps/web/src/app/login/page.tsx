// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { KestrelLogo } from "@/components/brand/kestrel-logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login } from "@/lib/actions/auth";
import { safeNextPath } from "@/lib/login-redirect";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; next?: string | string[] }>;
}) {
  const { error, next } = await searchParams;
  const nextPath = safeNextPath(next);

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 45% at 50% -10%, hsl(257 85% 60% / 0.22), transparent 55%)",
        }}
      />
      <form
        action={login}
        className="relative w-full max-w-sm space-y-5 rounded-lg border border-border bg-card p-6 shadow-sm"
      >
        <div className="space-y-3">
          <KestrelLogo height={36} />
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Sign in</h1>
            <p className="text-sm text-muted-foreground">Open-source security for SaaS.</p>
          </div>
        </div>
        {error === "not-initialized" ? (
          <div className="rounded-md border border-dashed border-border bg-muted/40 p-3">
            <p className="text-sm font-medium">Kestrel hasn&apos;t been initialized yet</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Run <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">kestrel init --seed</code>{" "}
              to create an organization and an admin operator, then sign in.
            </p>
          </div>
        ) : error === "unavailable" ? (
          <p role="alert" className="text-sm text-destructive">
            Kestrel can&apos;t sign you in right now: the API is unavailable. Try again in a moment, or ask an
            admin to check the api service.
          </p>
        ) : error === "rate-limited" ? (
          <p role="alert" className="text-sm text-destructive">
            Too many sign-in attempts. Wait a minute and try again.
          </p>
        ) : error === "locked" ? (
          <p role="alert" className="text-sm text-destructive">
            Too many incorrect codes, so this account is locked for 15 minutes. Try again after that, or ask an
            admin to reset your two-factor authentication.
          </p>
        ) : error === "mfa-expired" ? (
          <p role="alert" className="text-sm text-destructive">
            Your sign-in timed out or had too many incorrect codes. Sign in again.
          </p>
        ) : (
          error && (
            <p role="alert" className="text-sm text-destructive">
              Invalid email or password
            </p>
          )
        )}
        {nextPath ? <input type="hidden" name="next" value={nextPath} /> : null}
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="you@example.com"
              required
              autoFocus
              autoComplete="username"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              placeholder="Password"
              required
              autoComplete="current-password"
            />
          </div>
        </div>
        <Button type="submit" className="w-full">
          Sign in
        </Button>
      </form>
    </div>
  );
}
