// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { MfaEnrolment } from "@/components/mfa/mfa-enrolment";
import { Button } from "@/components/ui/button";
import { routeAfterEnrolment } from "@/lib/mfa";

/**
 * /mfa/setup's body. Whether MFA was already on is read once: activating
 * swaps the session cookie, which re-renders the page with MFA on, and that
 * must not replace the recovery codes still on screen.
 */
export function MfaSetupFlow({
  account,
  next,
  alreadyEnabled,
}: {
  account: string;
  next: string | null;
  alreadyEnabled: boolean;
}) {
  const router = useRouter();
  const [enabledAtLoad] = useState(alreadyEnabled);

  if (enabledAtLoad) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">Two-factor authentication is already on.</p>
        <Button asChild size="sm">
          <Link href={routeAfterEnrolment(next)}>Continue</Link>
        </Button>
      </div>
    );
  }

  return (
    <MfaEnrolment
      account={account}
      next={next}
      onDone={(continueTo) => {
        router.replace(continueTo);
        router.refresh();
      }}
    />
  );
}
