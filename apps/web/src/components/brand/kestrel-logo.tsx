// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

type KestrelLogoProps = {
  /** Visual height in CSS pixels; width scales with the canonical 612:160 lockup. */
  height?: number;
  className?: string;
  /** When set, wraps the mark in a link. */
  href?: string;
  /**
   * `"auto"` (default) swaps with the site theme — for surfaces whose
   * background follows light/dark mode (e.g. the login page).
   * `"dark"` always renders the dark-background (light-text) lockup — for a
   * surface that's a fixed dark tone regardless of theme, like the nav rail
   * (`bg-sidebar` is dark in both themes; see `brand/UI_STYLE_GUIDE.md`
   * "Surface layering"). `"light"` is the mirror, for a fixed light surface.
   */
  variant?: "auto" | "dark" | "light";
  /**
   * Also renders the icon-only mark (`.kestrel-logo-compact`) alongside the
   * wordmark (`.kestrel-logo-full`), inside the same wrapper/Link, so a
   * collapsed-sidebar CSS rule (see globals.css `[data-sidebar-collapsed]`)
   * can swap between them without the mark losing its click target. Only
   * meaningful with `variant="dark"` or `"light"` (a pinned surface) — not
   * supported with `"auto"`.
   */
  collapsible?: boolean;
};

const COMPACT_SRC = {
  dark: "/brand/kestrel-mark-white.svg",
  light: "/brand/kestrel-mark-color.svg",
} as const;

/**
 * Horizontal lockup (color mark + “Kestrel” wordmark). By default swaps
 * light/dark SVG with the site theme; pass `variant="dark"` / `"light"` to
 * pin it to a surface whose background doesn't follow the theme toggle.
 * Plain <img> keeps SVG CSS/media swapping simple (no next/image rasterization).
 */
export function KestrelLogo({
  height = 40,
  className = "",
  href,
  variant = "auto",
  collapsible = false,
}: KestrelLogoProps) {
  const width = Math.round((height * 612) / 160);
  const style = { height, width: "auto" as const, maxWidth: "100%" as const };
  const compactStyle = { height, width: height, maxWidth: "100%" as const };

  const compact =
    collapsible && (variant === "dark" || variant === "light") ? (
      // eslint-disable-next-line @next/next/no-img-element -- pinned SVG, no theme swap
      <img
        src={COMPACT_SRC[variant]}
        alt="Kestrel"
        width={height}
        height={height}
        className="kestrel-logo-compact object-contain object-left"
        style={compactStyle}
        decoding="async"
      />
    ) : null;

  const fullClassName = compact ? "kestrel-logo-full object-contain object-left" : "object-contain object-left";

  const images =
    variant === "dark" ? (
      <>
        {/* eslint-disable-next-line @next/next/no-img-element -- pinned SVG, no theme swap */}
        <img
          src="/brand/kestrel-logo-horizontal-dark.svg"
          alt={compact ? "" : "Kestrel"}
          aria-hidden={compact ? true : undefined}
          width={width}
          height={height}
          className={fullClassName}
          style={style}
          decoding="async"
        />
        {compact}
      </>
    ) : variant === "light" ? (
      <>
        {/* eslint-disable-next-line @next/next/no-img-element -- pinned SVG, no theme swap */}
        <img
          src="/brand/kestrel-logo-horizontal-light.svg"
          alt={compact ? "" : "Kestrel"}
          aria-hidden={compact ? true : undefined}
          width={width}
          height={height}
          className={fullClassName}
          style={style}
          decoding="async"
        />
        {compact}
      </>
    ) : (
      <>
        {/* eslint-disable-next-line @next/next/no-img-element -- SVG theme swap */}
        <img
          src="/brand/kestrel-logo-horizontal-light.svg"
          alt="Kestrel"
          width={width}
          height={height}
          className="kestrel-logo-light object-contain object-left"
          style={style}
          decoding="async"
        />
        {/* eslint-disable-next-line @next/next/no-img-element -- SVG theme swap */}
        <img
          src="/brand/kestrel-logo-horizontal-dark.svg"
          alt=""
          aria-hidden
          width={width}
          height={height}
          className="kestrel-logo-dark object-contain object-left"
          style={style}
          decoding="async"
        />
      </>
    );

  const wrapperClass = `inline-flex items-center ${className}`.trim();

  if (href) {
    return (
      <Link href={href} className={wrapperClass} aria-label="Kestrel home">
        {images}
      </Link>
    );
  }

  return <span className={wrapperClass}>{images}</span>;
}
