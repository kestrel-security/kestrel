// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState, useTransition } from "react";
import { Bell, CheckCheck, Settings } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  listRecentNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "@/lib/actions/notifications";
import {
  bellAriaLabel,
  markAllReadLocally,
  markReadLocally,
  notificationHref,
  unreadBadgeText,
} from "@/lib/notifications";
import type { InAppNotification, InAppNotificationList } from "@/lib/types";
import { absoluteTime, cn, relativeTime } from "@/lib/utils";

// The app layout is not re-rendered on client navigation, so the count it
// fetched would go stale; refresh it on this cadence while the tab is visible.
const POLL_INTERVAL_MS = 60_000;

const EMPTY: InAppNotificationList = { items: [], next_cursor: null, unread_count: 0 };

export function NotificationBell({ initial }: { initial: InAppNotificationList | null }) {
  const router = useRouter();
  const [list, setList] = useState<InAppNotificationList>(initial ?? EMPTY);
  const [error, setError] = useState<string | null>(null);
  const [loading, startLoading] = useTransition();

  const refresh = useCallback(() => {
    startLoading(async () => {
      const result = await listRecentNotifications();
      if (result.ok) {
        setList(result.data);
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const open = (item: InAppNotification) => {
    if (!item.is_read) {
      setList((current) => markReadLocally(current, item.id));
      void markNotificationRead(item.id);
    }
    const href = notificationHref(item);
    if (href) router.push(href);
  };

  const markAll = () => {
    setList((current) => markAllReadLocally(current));
    void markAllNotificationsRead().then((result) => {
      if (!result.ok) {
        setError(result.error);
        refresh();
      }
    });
  };

  const badge = unreadBadgeText(list.unread_count);

  return (
    <DropdownMenu
      onOpenChange={(isOpen) => {
        if (isOpen) refresh();
      }}
    >
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={bellAriaLabel(list.unread_count)}
          className="sidebar-bell relative flex size-8 shrink-0 items-center justify-center rounded-md text-sidebar-muted transition-colors duration-150 hover:bg-white/5 hover:text-sidebar-foreground data-[state=open]:bg-white/5 data-[state=open]:text-sidebar-foreground"
        >
          <Bell className="size-4" aria-hidden />
          {badge ? (
            <span
              aria-hidden
              className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-semibold leading-none text-primary-foreground"
            >
              {badge}
            </span>
          ) : null}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="right" align="start" sideOffset={8} className="w-80 p-0">
        <div className="flex items-center justify-between gap-2 px-3 py-2">
          <DropdownMenuLabel className="p-0">Notifications</DropdownMenuLabel>
          {list.unread_count > 0 ? (
            <Badge variant="default" className="tabular-nums">
              {list.unread_count} unread
            </Badge>
          ) : null}
        </div>
        <DropdownMenuSeparator className="mx-0 my-0" />

        <div className="max-h-96 overflow-y-auto p-1" aria-busy={loading}>
          {error ? (
            <p role="alert" className="px-2 py-3 text-sm text-destructive">
              {error}
            </p>
          ) : null}
          {list.items.length === 0 && !error ? (
            <p className="px-2 py-6 text-center text-sm text-muted-foreground">
              {loading ? "Loading…" : "You're all caught up."}
            </p>
          ) : null}
          {list.items.map((item) => (
            <DropdownMenuItem
              key={item.id}
              onSelect={() => open(item)}
              className="items-start gap-2.5 px-2 py-2"
            >
              <span
                aria-hidden
                className={cn(
                  "mt-1.5 size-2 shrink-0 rounded-full",
                  item.is_read ? "bg-transparent" : "bg-primary",
                )}
              />
              <span className="min-w-0 flex-1">
                <span
                  className={cn(
                    "block truncate text-sm",
                    item.is_read ? "text-muted-foreground" : "font-medium text-foreground",
                  )}
                >
                  {item.title}
                </span>
                {item.body ? (
                  <span className="block truncate text-xs text-muted-foreground">{item.body}</span>
                ) : null}
                <span
                  className="block text-[11px] text-muted-foreground"
                  title={absoluteTime(item.created_at)}
                >
                  {relativeTime(item.created_at)}
                  {item.is_read ? null : <span className="sr-only"> · unread</span>}
                </span>
              </span>
            </DropdownMenuItem>
          ))}
        </div>

        <DropdownMenuSeparator className="mx-0 my-0" />
        <div className="flex items-center justify-between gap-1 p-1">
          <DropdownMenuItem
            disabled={list.unread_count === 0}
            onSelect={(event) => {
              event.preventDefault();
              markAll();
            }}
            className="text-xs"
          >
            <CheckCheck aria-hidden />
            Mark all read
          </DropdownMenuItem>
          <DropdownMenuItem asChild className="text-xs">
            <Link href="/settings/notifications">
              <Settings aria-hidden />
              Settings
            </Link>
          </DropdownMenuItem>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
