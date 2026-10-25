// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";
import type { Operator } from "@/lib/types";

type NavItem = {
  href: string;
  label: string;
  adminOnly?: boolean;
};

const ACCOUNT_ITEMS: NavItem[] = [
  { href: "/settings/account", label: "Account" },
  { href: "/settings/notifications", label: "Notifications" },
];

const ORG_ITEMS: NavItem[] = [
  { href: "/settings/operators", label: "Operators", adminOnly: true },
  { href: "/settings/webhooks", label: "Webhooks", adminOnly: true },
  { href: "/settings/ticketing", label: "Ticketing", adminOnly: true },
  { href: "/settings/email", label: "Email", adminOnly: true },
  { href: "/settings/ai", label: "AI", adminOnly: true },
  { href: "/settings/audit", label: "Audit log", adminOnly: true },
];

function itemActive(pathname: string | null, href: string): boolean {
  if (!pathname) return false;
  return pathname === href || pathname.startsWith(`${href}/`);
}

function NavGroup({
  title,
  items,
  pathname,
}: {
  title: string;
  items: NavItem[];
  pathname: string | null;
}) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1">
      <p className="px-2 text-eyebrow">{title}</p>
      <ul className="space-y-0.5">
        {items.map((item) => {
          const active = itemActive(pathname, item.href);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "block rounded-md px-2 py-1.5 text-sm transition-colors duration-150",
                  active
                    ? "bg-primary/15 font-medium text-foreground ring-1 ring-inset ring-primary/30"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function SettingsNav({ role }: { role: Operator["role"] }) {
  const pathname = usePathname();
  const isAdmin = role === "admin";
  const orgItems = ORG_ITEMS.filter((item) => !item.adminOnly || isAdmin);

  return (
    <nav className="space-y-5" aria-label="Settings">
      <NavGroup title="Account" items={ACCOUNT_ITEMS} pathname={pathname} />
      {orgItems.length > 0 ? (
        <NavGroup title="Organization" items={orgItems} pathname={pathname} />
      ) : null}
    </nav>
  );
}
