// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { AuthPanel } from "@/components/auth/auth-panel";
import { MfaChallengeForm } from "@/components/auth/mfa-challenge-form";
import { safeNextPath } from "@/lib/login-redirect";
import { MFA_CHALLENGE_COOKIE_NAME } from "@/lib/mfa";

// Reached without a session: the proxy skips /login*, and what this page
// needs is the short-lived challenge cookie the login action set.
export default async function LoginMfaPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const { next } = await searchParams;
  const nextPath = safeNextPath(next);

  const cookieStore = await cookies();
  if (!cookieStore.has(MFA_CHALLENGE_COOKIE_NAME)) {
    const query = new URLSearchParams({ error: "mfa-expired" });
    if (nextPath) query.set("next", nextPath);
    redirect(`/login?${query.toString()}`);
  }

  return (
    <AuthPanel
      title="Two-factor authentication"
      description="Enter the code from your authenticator app to finish signing in."
    >
      <MfaChallengeForm next={nextPath} />
    </AuthPanel>
  );
}
