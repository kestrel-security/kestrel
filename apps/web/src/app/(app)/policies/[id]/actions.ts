// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { redirect } from "next/navigation";

import { ApiError } from "@/lib/api";
import {
  activatePolicyVersion,
  evaluatePolicyNow,
  forkPackPolicy,
  setPolicyEnabled,
} from "@/lib/actions/policies";
import { policyTabHref, policyTabHrefWith, type PolicyTab } from "@/lib/policy-tabs";

/**
 * Server actions for the policy detail workspace.
 *
 * These live beside the route rather than in `lib/actions/` so the shared
 * action module stays untouched, and so the header component can receive them
 * pre-bound (`action.bind(null, id)`) without the page having to declare
 * inline closures for each one.
 */

/**
 * Turn a 403 into a redirect carrying `?error=forbidden`, which the page renders
 * as a banner.
 *
 * `redirect()` signals by throwing `NEXT_REDIRECT`, so the rethrow below is
 * load-bearing: swallowing errors here would silently break every redirect,
 * including the success paths that call `redirect()` on purpose.
 */
async function runOrRedirectOnForbidden(
  id: string,
  tab: PolicyTab,
  action: () => Promise<unknown>,
): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      redirect(policyTabHrefWith(id, tab, { error: "forbidden" }));
    }
    throw error;
  }
}

export async function setPolicyEnabledAction(
  id: string,
  tab: PolicyTab,
  nextEnabled: boolean,
): Promise<void> {
  await runOrRedirectOnForbidden(id, tab, () => setPolicyEnabled(id, nextEnabled));
}

export async function evaluatePolicyAction(id: string, tab: PolicyTab): Promise<void> {
  await runOrRedirectOnForbidden(id, tab, async () => {
    const result = await evaluatePolicyNow(id);
    redirect(
      policyTabHrefWith(id, tab, {
        evaluated: "1",
        matches: result.matched_object_count,
        status: result.status,
      }),
    );
  });
}

export async function forkPolicyAction(id: string, tab: PolicyTab): Promise<void> {
  await runOrRedirectOnForbidden(id, tab, async () => {
    const forked = await forkPackPolicy(id);
    // Land on the fork's code tab — the whole point of forking is to edit.
    redirect(policyTabHref(forked.id, "code"));
  });
}

export async function activateVersionAction(id: string, formData: FormData): Promise<void> {
  const versionId = String(formData.get("version_id") ?? "");
  if (!versionId) return;
  await runOrRedirectOnForbidden(id, "versions", () => activatePolicyVersion(id, versionId));
}
