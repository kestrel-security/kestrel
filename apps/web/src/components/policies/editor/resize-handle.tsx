// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useCallback, useEffect, useRef } from "react";

import { cn } from "@/lib/utils";
import {
  EDITOR_HEIGHT_STEP,
  MAX_EDITOR_HEIGHT,
  MIN_EDITOR_HEIGHT,
} from "@/components/policies/editor/use-editor-height";

/**
 * Drag separator between the editor and the results drawer.
 *
 * Pointer moves are coalesced into one `requestAnimationFrame` commit: two
 * `automaticLayout: true` Monaco instances re-laying out on every raw
 * pointermove is enough to drop frames on a large policy.
 */
export function ResizeHandle({
  height,
  onResize,
  onReset,
  className,
}: {
  height: number;
  onResize: (next: number) => void;
  onReset: () => void;
  className?: string;
}) {
  const dragRef = useRef<{ startY: number; startHeight: number } | null>(null);
  const frameRef = useRef<number | null>(null);
  const pendingRef = useRef<number | null>(null);
  const onResizeRef = useRef(onResize);

  useEffect(() => {
    onResizeRef.current = onResize;
  }, [onResize]);

  useEffect(
    () => () => {
      if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
    },
    [],
  );

  const commit = useCallback((next: number) => {
    pendingRef.current = next;
    if (frameRef.current != null) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = null;
      const value = pendingRef.current;
      if (value != null) onResizeRef.current(value);
    });
  }, []);

  const handlePointerDown = useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    dragRef.current = { startY: event.clientY, startHeight: height };
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  }, [height]);

  const handlePointerMove = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      const drag = dragRef.current;
      if (!drag) return;
      commit(drag.startHeight + (event.clientY - drag.startY));
    },
    [commit],
  );

  const endDrag = useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    if (!dragRef.current) return;
    dragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        onResize(height + EDITOR_HEIGHT_STEP);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        onResize(height - EDITOR_HEIGHT_STEP);
      } else if (event.key === "Home" || event.key === "End") {
        event.preventDefault();
        onResize(event.key === "Home" ? MIN_EDITOR_HEIGHT : MAX_EDITOR_HEIGHT);
      }
    },
    [height, onResize],
  );

  return (
    <div
      role="separator"
      aria-orientation="horizontal"
      aria-label="Resize editor"
      aria-valuenow={height}
      aria-valuemin={MIN_EDITOR_HEIGHT}
      aria-valuemax={MAX_EDITOR_HEIGHT}
      tabIndex={0}
      title="Drag to resize · Arrow keys adjust · double-click to reset"
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onDoubleClick={onReset}
      onKeyDown={handleKeyDown}
      className={cn(
        "group flex h-3 cursor-row-resize touch-none items-center justify-center rounded-sm outline-none",
        "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        className,
      )}
    >
      <span
        className="h-1 w-16 rounded-full bg-border transition-colors duration-150 group-hover:bg-primary/50 group-focus-visible:bg-primary/50"
        aria-hidden
      />
    </div>
  );
}
