// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import type { ReactNode } from "react";

/**
 * An app-relative path: one leading "/" and not "//" or "/\\", which browsers
 * resolve as protocol-relative URLs to another host.
 */
export function isInAppHref(href: string): boolean {
  return /^\/(?![/\\])/.test(href);
}

/** An absolute http(s) URL, opened in a new tab. */
export function isExternalHref(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

/** Returns an in-app href, or null for an empty, external or unusable link. */
export function inAppFindingLink(href: string | null | undefined): string | null {
  if (!href) return null;
  return isInAppHref(href) ? href : null;
}

/**
 * Links a provider- or API-supplied href. Only app-relative paths become
 * client-side links; http(s) URLs open in a new tab; anything else
 * (protocol-relative "//host", "javascript:", relative paths) renders as text.
 */
export function FindingHref({
  href,
  children,
  className = "text-primary underline",
}: {
  href: string | null | undefined;
  children: ReactNode;
  className?: string;
}) {
  if (!href) return null;
  if (isInAppHref(href)) {
    return (
      <Link href={href} className={className}>
        {children}
      </Link>
    );
  }
  if (isExternalHref(href)) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
        {children}
      </a>
    );
  }
  return <span>{children}</span>;
}
