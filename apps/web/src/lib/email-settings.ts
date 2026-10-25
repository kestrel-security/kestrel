// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Field rules for Settings → Email, kept out of the component so switching
 * security mode and the re-enter-password check are testable.
 */

import type { EmailSecurity, EmailSettings, OrgEmailSettings } from "@/lib/types";

export const EMAIL_SECURITY_OPTIONS: { id: EmailSecurity; label: string }[] = [
  { id: "starttls", label: "STARTTLS" },
  { id: "ssl", label: "SSL/TLS" },
  { id: "none", label: "None" },
];

const DEFAULT_PORTS: Record<EmailSecurity, number> = {
  starttls: 587,
  ssl: 465,
  none: 25,
};

/** The conventional submission port for a security mode. */
export function defaultEmailPort(security: EmailSecurity): number {
  return DEFAULT_PORTS[security];
}

function sameHost(a: string | null | undefined, b: string | null | undefined): boolean {
  // Hostnames are case-insensitive; a trailing dot names the same host.
  const clean = (v: string | null | undefined) => (v ?? "").trim().toLowerCase().replace(/\.$/, "");
  return clean(a) === clean(b);
}

/**
 * Mirrors the API rule: the stored password is never sent to a different
 * server or account, so changing host, port or username with a password on
 * file requires typing it again in the same save.
 */
export function emailPasswordMustBeReentered(
  saved: Pick<OrgEmailSettings, "host" | "port" | "username" | "password_configured"> | null,
  edited: { host: string; port: number | string; username: string },
): boolean {
  if (!saved?.password_configured) return false;
  return (
    !sameHost(saved.host, edited.host) ||
    Number(edited.port) !== saved.port ||
    edited.username.trim() !== (saved.username ?? "").trim()
  );
}

export type EmailStatus = "org" | "environment" | "not_configured";

/** Which config is in force, for the page's status badge. */
export function emailStatus(settings: Pick<EmailSettings, "source">): EmailStatus {
  return settings.source ?? "not_configured";
}

const STATUS_LABELS: Record<EmailStatus, string> = {
  org: "Configured in Kestrel",
  environment: "From server environment",
  not_configured: "Not configured",
};

export function emailStatusLabel(settings: Pick<EmailSettings, "source">): string {
  return STATUS_LABELS[emailStatus(settings)];
}
