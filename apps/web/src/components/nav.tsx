// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  FileCode2,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  PanelLeft,
  PanelLeftClose,
  Plug,
  Search,
  Settings,
  ShieldAlert,
  Users,
  X,
} from "lucide-react";

import { KestrelLogo } from "@/components/brand/kestrel-logo";
import { NotificationBell } from "@/components/notification-bell";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useSidebarCollapsed } from "@/hooks/use-sidebar-collapsed";
import { logout } from "@/lib/actions/auth";
import { cn } from "@/lib/utils";
import type { InAppNotificationList, Operator } from "@/lib/types";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/connectors", label: "Integrations", icon: Plug },
  { href: "/identities", label: "Identities", icon: Users },
  { href: "/explore", label: "Explore", icon: Network },
  { href: "/changes", label: "Changes", icon: GitBranch },
  { href: "/policies", label: "Policies", icon: FileCode2 },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
] as const;

function navItemActive(pathname: string | null, href: string): boolean {
  if (!pathname) return false;
  if (href === "/dashboard") return pathname === "/dashboard" || pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

function SidebarTooltip({
  label,
  disabled,
  children,
}: {
  label: string;
  disabled: boolean;
  children: ReactNode;
}) {
  if (disabled) return <>{children}</>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={8}>
        {label}
      </TooltipContent>
    </Tooltip>
  );
}

const MD_QUERY = "(max-width: 767.98px)";

/** True below Tailwind's md breakpoint, where the sidebar is a drawer. False on the server. */
function useIsBelowMd(): boolean {
  const [below, setBelow] = useState(false);
  useEffect(() => {
    const query = window.matchMedia(MD_QUERY);
    const update = () => setBelow(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return below;
}

export function Nav({
  operator,
  notifications,
}: {
  operator: Operator;
  notifications: InAppNotificationList | null;
}) {
  const pathname = usePathname();
  const settingsActive = Boolean(pathname?.startsWith("/settings"));
  const { collapsed: storedCollapsed, toggle } = useSidebarCollapsed();
  const operatorLabel = operator.display_name ?? operator.email;

  // Below md the sidebar is a drawer. It remembers the path it was opened on,
  // so any navigation (a link here, the command palette, back) closes it
  // without an effect; links also close it when they point at the current page.
  const [drawerOpenedAt, setDrawerOpenedAt] = useState<string | null>(null);
  const drawerOpen = drawerOpenedAt !== null && drawerOpenedAt === pathname;
  const openDrawer = () => setDrawerOpenedAt(pathname ?? "");
  const closeDrawer = () => setDrawerOpenedAt(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const isMobile = useIsBelowMd();
  // The icon rail only exists from md up; the drawer always shows labels.
  const collapsed = storedCollapsed && !isMobile;

  // The drawer is the same <nav> as the md+ rail, so it can't move into a
  // portalled Radix Dialog without rendering the sidebar twice. It gets the
  // dialog behaviour by hand instead: focus moves in on open, Tab stays inside,
  // Escape closes, and focus returns to whatever opened it.
  const navRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!drawerOpen) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButtonRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerOpenedAt(null);
        return;
      }
      if (event.key !== "Tab" || !navRef.current) return;
      const focusable = Array.from(
        navRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => el.offsetParent !== null);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const inside = navRef.current.contains(document.activeElement);
      if (event.shiftKey && (document.activeElement === first || !inside)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !inside)) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      if (opener?.isConnected) opener.focus();
    };
  }, [drawerOpen]);

  return (
    <TooltipProvider delayDuration={150}>
      <div className="flex h-14 shrink-0 items-center gap-2 border-b border-sidebar-border bg-sidebar px-3 text-sidebar-foreground md:hidden">
        <button
          type="button"
          onClick={openDrawer}
          aria-expanded={drawerOpen}
          aria-controls="kestrel-sidebar"
          aria-label="Open navigation"
          className="flex size-9 shrink-0 items-center justify-center rounded-md text-sidebar-muted transition-colors duration-150 hover:bg-white/5 hover:text-sidebar-foreground"
        >
          <Menu className="size-5" aria-hidden />
        </button>
        <KestrelLogo href="/dashboard" height={26} variant="dark" />
        <button
          type="button"
          aria-label="Search or jump to…"
          className="ml-auto flex size-9 shrink-0 items-center justify-center rounded-md text-sidebar-muted transition-colors duration-150 hover:bg-white/5 hover:text-sidebar-foreground"
          onClick={() => {
            window.dispatchEvent(new CustomEvent("kestrel:open-command-palette"));
          }}
        >
          <Search className="size-4" aria-hidden />
        </button>
      </div>
      {drawerOpen ? (
        <div className="fixed inset-0 z-40 bg-black/50 md:hidden" aria-hidden onClick={closeDrawer} />
      ) : null}
      <nav
        ref={navRef}
        id="kestrel-sidebar"
        aria-label="Primary"
        aria-modal={drawerOpen ? true : undefined}
        role={drawerOpen ? "dialog" : undefined}
        className={cn(
          "kestrel-nav fixed inset-y-0 left-0 z-50 flex h-full shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground md:static md:z-auto md:visible md:translate-x-0",
          drawerOpen ? "translate-x-0 shadow-xl" : "invisible -translate-x-full",
        )}
      >
        <div className="sidebar-header flex flex-col gap-3 px-4 pb-3 pt-5">
          <div className="sidebar-brand flex items-center justify-between gap-1">
            <KestrelLogo href="/dashboard" height={32} variant="dark" collapsible />
            <div className="sidebar-brand-actions flex items-center gap-1">
              <NotificationBell initial={notifications} />
              <button
                ref={closeButtonRef}
                type="button"
                onClick={closeDrawer}
                aria-label="Close navigation"
                className="flex size-8 shrink-0 items-center justify-center rounded-md text-sidebar-muted transition-colors duration-150 hover:bg-white/5 hover:text-sidebar-foreground md:hidden"
              >
                <X className="size-4" aria-hidden />
              </button>
              <SidebarTooltip
                label={collapsed ? "Expand navigation" : "Collapse navigation"}
                disabled={false}
              >
                <button
                  type="button"
                  onClick={toggle}
                  aria-expanded={!collapsed}
                  aria-controls="kestrel-sidebar"
                  aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
                  className="sidebar-toggle hidden size-8 shrink-0 md:flex items-center justify-center rounded-md text-sidebar-muted transition-colors duration-150 hover:bg-white/5 hover:text-sidebar-foreground"
                >
                  {collapsed ? (
                    <PanelLeft className="size-4" aria-hidden />
                  ) : (
                    <PanelLeftClose className="size-4" aria-hidden />
                  )}
                </button>
              </SidebarTooltip>
            </div>
          </div>
          <SidebarTooltip label="Search or jump to…" disabled={!collapsed}>
            <button
              type="button"
              aria-label="Search or jump to…"
              className="sidebar-search flex w-full items-center gap-2 rounded-md border border-sidebar-border bg-black/15 px-2.5 py-1.5 text-left text-xs text-sidebar-muted transition-colors duration-150 hover:border-primary/30 hover:bg-black/25 hover:text-sidebar-foreground"
              onClick={() => {
                closeDrawer();
                window.dispatchEvent(new CustomEvent("kestrel:open-command-palette"));
              }}
            >
              <Search className="size-3.5 shrink-0" aria-hidden />
              <span className="sidebar-label flex-1">Search or jump to…</span>
              <kbd className="sidebar-label rounded border border-sidebar-border bg-black/20 px-1 font-mono text-[10px]">
                ⌘K
              </kbd>
            </button>
          </SidebarTooltip>
        </div>

        <div className="flex flex-1 flex-col gap-0.5 px-3 pt-1">
          <p className="sidebar-label text-eyebrow px-2 pb-1 text-sidebar-muted">Operate</p>
          {NAV_ITEMS.map((item) => {
            const active = navItemActive(pathname, item.href);
            const Icon = item.icon;
            return (
              <SidebarTooltip key={item.href} label={item.label} disabled={!collapsed}>
                <Link
                  href={item.href}
                  onClick={closeDrawer}
                  aria-label={item.label}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "sidebar-nav-link group relative flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors duration-150",
                    active
                      ? "bg-primary/15 font-medium text-white ring-1 ring-inset ring-primary/30"
                      : "text-sidebar-muted hover:bg-white/5 hover:text-sidebar-foreground",
                  )}
                >
                  {active ? (
                    <span
                      aria-hidden
                      className="sidebar-active-pip absolute -left-3 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full"
                      style={{ background: "var(--kestrel-gradient)" }}
                    />
                  ) : null}
                  <Icon
                    className={cn(
                      "size-4 shrink-0",
                      active ? "text-primary" : "opacity-70 group-hover:opacity-100",
                    )}
                    aria-hidden
                  />
                  <span className="sidebar-label">{item.label}</span>
                </Link>
              </SidebarTooltip>
            );
          })}

          <Separator className="my-3 bg-sidebar-border" />

          <SidebarTooltip label="Settings" disabled={!collapsed}>
            <Link
              href="/settings"
              onClick={closeDrawer}
              aria-label="Settings"
              aria-current={settingsActive ? "page" : undefined}
              className={cn(
                "sidebar-nav-link flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors duration-150",
                settingsActive
                  ? "bg-primary/15 font-medium text-white ring-1 ring-inset ring-primary/30"
                  : "text-sidebar-muted hover:bg-white/5 hover:text-sidebar-foreground",
              )}
            >
              <Settings
                className={cn("size-4 shrink-0", settingsActive ? "text-primary" : "opacity-70")}
                aria-hidden
              />
              <span className="sidebar-label">Settings</span>
            </Link>
          </SidebarTooltip>
        </div>

        <div className="mt-auto border-t border-sidebar-border p-3">
          <ThemeToggle />
          <SidebarTooltip label="Account settings" disabled={!collapsed}>
            <Link
              href="/settings/account"
              onClick={closeDrawer}
              aria-label={`Account settings for ${operatorLabel}`}
              className="sidebar-operator mb-2 mt-1 flex items-center gap-2 rounded-md px-1 py-1 transition-colors duration-150 hover:bg-white/5"
            >
              <div
                className="flex size-7 shrink-0 items-center justify-center rounded-md text-[10px] font-semibold uppercase text-white"
                style={{ background: "var(--kestrel-gradient)" }}
                aria-hidden
              >
                {operatorLabel.slice(0, 2)}
              </div>
              <div className="sidebar-label min-w-0 flex-1">
                <p className="truncate text-xs font-medium text-sidebar-foreground">{operatorLabel}</p>
                <p className="truncate text-[11px] capitalize text-sidebar-muted">
                  {operator.role.replace("_", " ")}
                </p>
              </div>
            </Link>
          </SidebarTooltip>
          <form action={logout}>
            <SidebarTooltip label="Sign out" disabled={!collapsed}>
              <Button
                type="submit"
                variant="ghost"
                size="sm"
                aria-label="Sign out"
                className="sidebar-sign-out w-full justify-start text-sidebar-muted hover:bg-white/5 hover:text-sidebar-foreground"
              >
                <LogOut className="size-3.5" aria-hidden />
                <span className="sidebar-label">Sign out</span>
              </Button>
            </SidebarTooltip>
          </form>
        </div>
      </nav>
    </TooltipProvider>
  );
}
