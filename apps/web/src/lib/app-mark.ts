// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Resolve SaaS application marks for Explore / findings graph UI.
 *
 * `microsoft_365` outlives the connector, which was removed: an OAuth app
 * literally named "Microsoft Teams" is still discovered through Slack, Okta,
 * or Google Workspace and should render its own mark, and existing databases
 * keep `application_type = microsoft_365` rows that Postgres cannot drop from
 * the enum. Marks are a display concern, not a connector catalogue.
 */

export type KnownAppMark =
  | "github"
  | "slack"
  | "okta"
  | "google_workspace"
  | "microsoft_365";

export type ResolvedAppMark =
  | { kind: "vendor"; key: KnownAppMark; label: string }
  | { kind: "letter"; letter: string; label: string };

export const KNOWN_APP_MARKS: readonly KnownAppMark[] = [
  "github",
  "slack",
  "okta",
  "google_workspace",
  "microsoft_365",
] as const;

export const APP_MARK_LABELS: Record<KnownAppMark, string> = {
  github: "GitHub",
  slack: "Slack",
  okta: "Okta",
  google_workspace: "Google Workspace",
  microsoft_365: "Microsoft 365",
};

/** OAuth app display-name aliases → vendor mark (case-insensitive substring). */
const OAUTH_NAME_ALIASES: { pattern: RegExp; key: KnownAppMark }[] = [
  { pattern: /\bgithub\b/i, key: "github" },
  { pattern: /\bslack\b/i, key: "slack" },
  { pattern: /\bokta\b/i, key: "okta" },
  { pattern: /\bgoogle\b|\bgws\b|\bworkspace\b/i, key: "google_workspace" },
  { pattern: /\bmicrosoft\b|\bm365\b|\boffice\s*365\b|\bentra\b|\bazure\s*ad\b/i, key: "microsoft_365" },
];

const CONNECTOR_TYPE_ALIASES: Record<string, KnownAppMark> = {
  github: "github",
  slack: "slack",
  okta: "okta",
  google_workspace: "google_workspace",
  gws: "google_workspace",
  microsoft_365: "microsoft_365",
  m365: "microsoft_365",
  entra: "microsoft_365",
  microsoft365: "microsoft_365",
};

function asString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function letterFromLabel(label: string): string {
  const cleaned = label.replace(/[^a-zA-Z0-9]/g, "");
  return (cleaned.charAt(0) || "?").toUpperCase();
}

function vendorFromConnectorType(raw: string | null | undefined): KnownAppMark | null {
  if (!raw) return null;
  const key = raw.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return CONNECTOR_TYPE_ALIASES[key] ?? null;
}

function vendorFromOauthName(name: string | null | undefined): KnownAppMark | null {
  if (!name) return null;
  for (const { pattern, key } of OAUTH_NAME_ALIASES) {
    if (pattern.test(name)) return key;
  }
  return null;
}

export type ResolveAppMarkInput = {
  /** Graph / catalog connector type (`github`, `okta`, …). */
  applicationType?: string | null;
  /** Node type — when `oauth_application`, prefer name aliases. */
  nodeType?: string | null;
  /** Node label or OAuth app display name. */
  label?: string | null;
  /** Extra name from properties (e.g. `properties.name`). */
  name?: string | null;
  /** OAuth publisher / vendor hint when application_type is absent. */
  publisher?: string | null;
};

/**
 * Resolve which mark to show for a graph node or account row.
 *
 * Priority for oauth_application: OAuth name alias → application_type → publisher → letter.
 * Otherwise: application_type → letter.
 */
export function resolveAppMark(input: ResolveAppMarkInput): ResolvedAppMark {
  const label =
    asString(input.label) ||
    asString(input.name) ||
    asString(input.applicationType) ||
    "App";
  const isOauth = input.nodeType === "oauth_application";

  if (isOauth) {
    const fromName =
      vendorFromOauthName(input.label) || vendorFromOauthName(input.name);
    if (fromName) {
      return { kind: "vendor", key: fromName, label: APP_MARK_LABELS[fromName] };
    }
  }

  const fromType =
    vendorFromConnectorType(input.applicationType) ||
    vendorFromConnectorType(input.publisher);
  if (fromType) {
    return { kind: "vendor", key: fromType, label: APP_MARK_LABELS[fromType] };
  }

  // Non-OAuth nodes with a recognizable label still get a vendor mark.
  if (!isOauth) {
    const fromLabel =
      vendorFromOauthName(input.label) || vendorFromOauthName(input.name);
    if (fromLabel) {
      return { kind: "vendor", key: fromLabel, label: APP_MARK_LABELS[fromLabel] };
    }
  }

  return { kind: "letter", letter: letterFromLabel(label), label };
}

/** Collect up to `limit` distinct marks from a list of application types. */
export function resolveAppMarksFromTypes(
  applicationTypes: string[] | null | undefined,
  limit = 3,
): { marks: ResolvedAppMark[]; overflow: number } {
  const seen = new Set<string>();
  const marks: ResolvedAppMark[] = [];
  for (const raw of applicationTypes ?? []) {
    const resolved = resolveAppMark({ applicationType: raw });
    const key =
      resolved.kind === "vendor" ? `v:${resolved.key}` : `l:${resolved.letter}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (marks.length < limit) marks.push(resolved);
  }
  const total = seen.size;
  return { marks, overflow: Math.max(0, total - marks.length) };
}

/** Pull application_type / name from graph node properties. */
export function resolveAppMarkFromNode(options: {
  nodeType: string;
  label: string;
  properties?: Record<string, unknown> | null;
}): ResolvedAppMark {
  const props = options.properties ?? {};
  return resolveAppMark({
    nodeType: options.nodeType,
    label: options.label,
    applicationType: asString(props.application_type),
    name: asString(props.name),
    publisher: asString(props.publisher),
  });
}
