// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound, redirect } from "next/navigation";

import { policyTabHref } from "@/lib/policy-tabs";
import { isUuid } from "@/lib/route-params";

/**
 * The evaluation log now lives in the policy workspace's Evaluations tab.
 * Kept as a redirect so existing links and bookmarks resolve to the one
 * canonical destination.
 */
export default async function PolicyEvaluationsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  if (!isUuid(id)) notFound();
  redirect(policyTabHref(id, "evaluations"));
}
