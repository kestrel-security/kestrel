// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Which key presses a page-level shortcut handler may claim. A handler on
 * `window` sees every keydown on the page, so it must leave alone the ones
 * meant for whatever the operator is actually interacting with.
 */

/** Something that types text: shortcuts would eat letters. */
const TYPING_SELECTOR = "input, textarea, select, [contenteditable]:not([contenteditable='false'])";

/** Widgets that move their own selection with the arrow keys. */
const ARROW_OWNER_SELECTOR = [
  "[role=dialog]",
  "[role=alertdialog]",
  "[role=menu]",
  "[role=menuitem]",
  "[role=listbox]",
  "[role=option]",
  "[role=combobox]",
  "[role=tablist]",
].join(", ");

/** Anything whose own Enter/Space/letter handling must win. */
const INTERACTIVE_SELECTOR = [
  TYPING_SELECTOR,
  ARROW_OWNER_SELECTOR,
  "a[href]",
  "button",
  "summary",
  "[role=button]",
  "[role=link]",
  "[role=checkbox]",
  "[role=switch]",
  "[role=tab]",
].join(", ");

type Closest = { closest(selector: string): unknown };

function within(target: unknown, selector: string): boolean {
  if (!target || typeof (target as Closest).closest !== "function") return false;
  return (target as Closest).closest(selector) != null;
}

/** j/k/arrow navigation: skip typing targets and widgets with their own arrow keys. */
export function blocksNavigationShortcut(target: unknown): boolean {
  return within(target, TYPING_SELECTOR) || within(target, ARROW_OWNER_SELECTOR);
}

/** Enter/x/o/Escape actions: skip any interactive element (links, buttons, menus, dialogs, ...). */
export function blocksActionShortcut(target: unknown): boolean {
  return within(target, INTERACTIVE_SELECTOR);
}
