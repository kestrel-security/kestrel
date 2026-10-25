// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { api } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { OrgSearchResponse } from "@/lib/types";

/** Org-wide ⌘K entity search. */
export async function orgSearch(
  q: string,
  limitPerType = 8,
): Promise<
  | { ok: true; data: OrgSearchResponse }
  | { ok: false; error: string }
> {
  try {
    const params = new URLSearchParams();
    params.set("q", q);
    params.set("limit_per_type", String(limitPerType));
    const data = await api.get<OrgSearchResponse>(`/search?${params}`);
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
