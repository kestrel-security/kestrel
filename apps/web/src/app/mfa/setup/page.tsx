// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { AuthPanel } from "@/components/auth/auth-panel";
import { MfaSetupFlow } from "@/components/mfa/mfa-setup-flow";
import { Button } from "@/components/ui/button";
import { logout } from "@/lib/actions/auth";
import { api } from "@/lib/api";
import { safeNextPath } from "@/lib/login-redirect";
import type { MfaStatus, Operator } from "@/lib/types";

// Outside the (app) layout on purpose: that layout sends a session limited to
// enrolment here, and this page must work for one. The proxy still
// requires the session cookie; /auth/me and /auth/mfa accept either kind of
// session, and an invalid one is a 401 that lib/api.ts sends to /login.
export default async function MfaSetupPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const { next } = await searchParams;
  const [operator, status] = await Promise.all([
    api.get<Operator>("/auth/me"),
    api.get<MfaStatus>("/auth/mfa"),
  ]);
  const required = operator.mfa_enrollment_required || status.required_by_org;

  return (
    <AuthPanel
      className="max-w-md"
      title="Set up two-factor authentication"
      description={
        required
          ? "Your organization requires a second step at sign-in. Set it up to continue."
          : "Add a second step at sign-in."
      }
    >
      <p className="text-sm">
        Signed in as <span className="font-medium">{operator.email}</span>
      </p>
      <MfaSetupFlow
        account={operator.email}
        next={safeNextPath(next)}
        alreadyEnabled={status.enabled}
      />
      <form action={logout} className="border-t border-border pt-4">
        <Button type="submit" variant="link" size="sm" className="h-auto px-0 text-muted-foreground">
          Sign out
        </Button>
      </form>
    </AuthPanel>
  );
}
