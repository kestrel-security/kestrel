// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactElement } from "react";

import { NotInitialized } from "@/components/not-initialized";
import { EmptyState } from "@/components/ui/empty-state";
import { isApiUnreachable, isNotInitialized } from "@/lib/api-state";

/** The web server got no answer from the API (it is down, or API_URL is wrong). */
export function ApiUnavailable() {
  return (
    <EmptyState
      title="Can't reach the Kestrel API"
      hint="The web server could not connect to the API. Check that the api service is running and that API_URL points at it; the web server log names the address it tried. Then reload this page."
    />
  );
}

/**
 * The page to render instead of the requested one when an API call failed
 * because of the deployment's state rather than the request: Kestrel not set
 * up yet, or the API not reachable. Null for any other error, which the
 * caller handles (notFound, rethrow, ...).
 */
export function apiStatePage(error: unknown): ReactElement | null {
  if (isNotInitialized(error)) return <NotInitialized />;
  if (isApiUnreachable(error)) return <ApiUnavailable />;
  return null;
}
