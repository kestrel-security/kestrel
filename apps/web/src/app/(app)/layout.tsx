// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { CommandPalette } from "@/components/command-palette";
import { ToastProvider } from "@/components/ui/toast";
import { Nav } from "@/components/nav";
import { api, orFallback } from "@/lib/api";
import { isApiUnreachable, isNotInitialized } from "@/lib/api-state";
import { REQUEST_PATH_HEADER } from "@/lib/constants";
import { safeNextPath } from "@/lib/login-redirect";
import { withNext } from "@/lib/mfa";
import { BELL_LIST_LIMIT } from "@/lib/notifications";
import type { InAppNotificationList, Operator } from "@/lib/types";

// Fetching /auth/me here (rather than in every page) is what actually
// enforces "you must be logged in" for this whole route group: the proxy
// only checks that a session cookie exists, not that it's still valid --
// an expired/revoked token gets caught by this call's 401, which
// lib/api.ts's request() turns into a redirect to /login.
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  let operator: Operator;
  try {
    operator = await api.get<Operator>("/auth/me");
  } catch (err) {
    // No app shell without an operator. Fixed copy only: err.message can be
    // the API's raw JSON body.
    if (isApiUnreachable(err) || isNotInitialized(err)) {
      return (
        <main className="mx-auto max-w-xl p-8">
          <h1 className="text-lg font-semibold">
            {isNotInitialized(err) ? "Kestrel hasn't been initialized yet" : "API is not reachable"}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            {isNotInitialized(err)
              ? "Run `kestrel init --seed` to create an organization and an admin operator, then sign in."
              : "The web server could not connect to the Kestrel API. Check that the api service is running and that API_URL points at it; the web server log names the address it tried."}
          </p>
        </main>
      );
    }
    throw err;
  }

  // The organization requires MFA and this operator signed in without it:
  // the session reaches nothing but setup until they enrol.
  if (operator.mfa_enrollment_required) {
    redirect(withNext("/mfa/setup", safeNextPath((await headers()).get(REQUEST_PATH_HEADER))));
  }

  // The bell is secondary chrome: if its fetch fails, render the page without
  // it rather than failing the whole app shell. The bell retries on open.
  const notifications = await api
    .get<InAppNotificationList>(`/notifications?limit=${BELL_LIST_LIMIT}`)
    .catch(orFallback(null));

  return (
    <ToastProvider>
      {/* Below md: a top bar with the menu button above the page, and the
          sidebar as a drawer (components/nav.tsx). From md up: rail + page. */}
      <div className="flex h-screen flex-col bg-background md:flex-row">
        <Nav operator={operator} notifications={notifications} />
        <main className="min-w-0 flex-1 overflow-auto p-4 md:p-6">{children}</main>
        <CommandPalette />
      </div>
    </ToastProvider>
  );
}
