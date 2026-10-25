// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Compact Explore edge labels. */

export type GraphLabelMode = "compact" | "hover" | "off";

export const EDGE_TYPE_LABELS: Record<string, string> = {
  member_of: "member of",
  assigned_role: "assigned",
  grants_permission: "grants",
  has_permission: "has perm",
  can_access: "can access",
  applies_to: "applies to",
  possesses_scope: "OAuth",
  supported_by: "supported by",
  maps_to: "maps to",
};

export type OAuthScopeLike = { name: string; is_sensitive?: boolean };

export function edgeTypeLabel(edgeType: string): string {
  return EDGE_TYPE_LABELS[edgeType] ?? edgeType.replace(/_/g, " ");
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function scopesFromProperties(properties: Record<string, unknown> | null | undefined): OAuthScopeLike[] {
  const raw = properties?.scopes;
  if (!Array.isArray(raw)) return [];
  const out: OAuthScopeLike[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const name = asString((item as { name?: unknown }).name);
    if (!name) continue;
    out.push({
      name,
      is_sensitive: Boolean((item as { is_sensitive?: unknown }).is_sensitive),
    });
  }
  return out;
}

/** Compact mid-edge label: permission / membership / sensitive scope / verb. */
export function compactEdgeLabel(
  edgeType: string,
  properties: Record<string, unknown> | null | undefined = {},
): string {
  const permission = asString(properties?.permission_level);
  if (permission) return permission;

  const membership = asString(properties?.membership_role);
  if (membership && edgeType === "member_of") return membership;

  if (edgeType === "possesses_scope") {
    const scopes = scopesFromProperties(properties);
    const sensitive = scopes.find((s) => s.is_sensitive);
    if (sensitive) return sensitive.name;
    if (scopes[0]) return scopes[0].name;
    return "OAuth";
  }

  return edgeTypeLabel(edgeType);
}

/** Hover / tooltip text: explanation preferred, else verb · access path · scopes. */
export function edgeHoverText(options: {
  edgeType: string;
  accessPath: string | null | undefined;
  properties?: Record<string, unknown> | null;
  explanation?: string | null;
}): string {
  if (options.explanation?.trim()) return options.explanation.trim();

  const parts = [edgeTypeLabel(options.edgeType)];
  if (options.accessPath) parts.push(options.accessPath.replace(/_/g, " "));
  const permission = asString(options.properties?.permission_level);
  if (permission) parts.push(permission);
  const membership = asString(options.properties?.membership_role);
  if (membership) parts.push(membership);
  const scopes = scopesFromProperties(options.properties);
  if (scopes.length) {
    parts.push(scopes.map((s) => (s.is_sensitive ? `${s.name}*` : s.name)).join(", "));
  }
  return parts.join(" · ");
}

export function nodeChipLabel(
  nodeType: string,
  properties: Record<string, unknown> | null | undefined,
  incomingPermission?: string | null,
): string | null {
  if (nodeType === "role" && properties?.is_privileged === true) return "Privileged";
  if (incomingPermission) return incomingPermission;
  if (nodeType === "oauth_application") {
    const scopes = scopesFromProperties(properties);
    const sensitive = scopes.find((s) => s.is_sensitive);
    if (sensitive) return sensitive.name;
  }
  return null;
}
