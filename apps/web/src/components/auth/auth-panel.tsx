// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

import { KestrelLogo } from "@/components/brand/kestrel-logo";
import { cn } from "@/lib/utils";

/**
 * The centred card on a tinted backdrop that the sign-in pages share
 * (/login/mfa, /mfa/setup), matching /login.
 */
export function AuthPanel({
  title,
  description,
  children,
  className,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4 py-8">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 45% at 50% -10%, hsl(257 85% 60% / 0.22), transparent 55%)",
        }}
      />
      <main
        className={cn(
          "relative w-full max-w-sm space-y-5 rounded-lg border border-border bg-card p-6 shadow-sm",
          className,
        )}
      >
        <div className="space-y-3">
          <KestrelLogo height={36} />
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
            {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
          </div>
        </div>
        {children}
      </main>
    </div>
  );
}
