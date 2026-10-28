// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Worker type vocabulary shared with `kestrel.db.models.identity.WorkerType`.
 * Pure and dependency-free so it can be unit-tested.
 */

import type { ClassificationMatchKind, WorkerType } from "@/lib/types";

export const WORKER_TYPES: readonly WorkerType[] = [
  "employee",
  "contractor",
  "vendor_or_partner",
  "guest",
  "service",
  "unknown",
] as const;

export const WORKER_TYPE_LABELS: Record<WorkerType, string> = {
  employee: "Employee",
  contractor: "Contractor",
  vendor_or_partner: "Vendor / partner",
  guest: "Guest",
  service: "Service account",
  unknown: "Unknown",
};

export const MATCH_KIND_LABELS: Record<ClassificationMatchKind, string> = {
  email_domain: "Email domain",
  org_unit_path_prefix: "Org unit path",
  group_name: "Group name",
  user_type: "Provider user type",
  application_type: "Application type",
};

export const MATCH_KIND_HINTS: Record<ClassificationMatchKind, string> = {
  email_domain: "vendor.example (also matches subdomains)",
  org_unit_path_prefix: "/Contractors (and everything beneath it)",
  group_name: "contractors-* (shell glob, case-insensitive)",
  user_type: "Contract* (the provider's own user type field)",
  application_type: "slack",
};

export function isWorkerType(value: unknown): value is WorkerType {
  return typeof value === "string" && (WORKER_TYPES as readonly string[]).includes(value);
}

/** A `?worker_type=` query value worth forwarding to the API. */
export function isWorkerTypeFilter(value: string | undefined): value is WorkerType {
  return isWorkerType(value);
}

/**
 * Which badge a worker type gets in a list, or null for the ones that say
 * nothing (`unknown`) or are already shown another way (`service` is the
 * identity type column; `employee` is the default and would be noise).
 */
export function workerTypeBadge(value: unknown): "outline" | "secondary" | null {
  if (!isWorkerType(value)) return null;
  switch (value) {
    case "contractor":
    case "vendor_or_partner":
      return "secondary";
    case "guest":
      return "outline";
    default:
      return null;
  }
}

/** Human text for `worker_type_source`. */
export function describeWorkerTypeSource(source: string | null | undefined): string {
  if (!source) return "not classified";
  if (source === "connector") return "from the provider's profile";
  if (source.startsWith("rule:")) return "from a classification rule";
  return source;
}
