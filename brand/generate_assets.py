# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Generate Kestrel's canonical SVG brand asset suite.

The two-path bird geometry in this file is the source of truth. Run this script
from the repository root after changing the mark, palette, or lockup spacing.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRAND_ASSETS = ROOT / "brand" / "assets"
WEB_BRAND = ROOT / "apps" / "web" / "public" / "brand"

INK = "#090C11"
DARK_SLATE = "#0F1117"
WHITE = "#F8FAFC"
VIOLET = "#7441F0"
PERIWINKLE = "#5D61F1"
BLUE = "#4689ED"

MARK_PATHS = """
  <path d="M8 20h45l45 42v45l-7.5-3L8 20Z" fill="url(#kestrel-gradient)"/>
  <path d="M87.5 20h27l18 18h-30l-6 9-18-19.5 9-7.5Z" fill="url(#kestrel-head-gradient)"/>
""".strip()

SIMPLE_MARK_PATHS = """
  <path d="M8 20h45l45 42v45l-7.5-3L8 20Z"/>
  <path d="M87.5 20h27l18 18h-30l-6 9-18-19.5 9-7.5Z"/>
""".strip()


def defs() -> str:
    return f"""
  <defs>
    <linearGradient id="kestrel-gradient" x1="8" y1="20" x2="98" y2="107" gradientUnits="userSpaceOnUse">
      <stop stop-color="{VIOLET}"/>
      <stop offset=".52" stop-color="{PERIWINKLE}"/>
      <stop offset="1" stop-color="{BLUE}"/>
    </linearGradient>
    <linearGradient id="kestrel-head-gradient" x1="79" y1="20" x2="132.5" y2="47" gradientUnits="userSpaceOnUse">
      <stop stop-color="{VIOLET}"/>
      <stop offset=".52" stop-color="{PERIWINKLE}"/>
      <stop offset="1" stop-color="{BLUE}"/>
    </linearGradient>
  </defs>""".rstrip()


def svg(view_box: str, body: str, title: str, *, width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="{view_box}" role="img" aria-labelledby="title">\n'
        f'  <title id="title">{title}</title>\n{body}\n</svg>\n'
    )


def mark_group(transform: str = "") -> str:
    attr = f' transform="{transform}"' if transform else ""
    return f"{defs()}\n  <g{attr}>\n    {MARK_PATHS.replace(chr(10), chr(10) + '    ')}\n  </g>"


def mono_mark_group(fill: str, transform: str = "") -> str:
    attr = f' transform="{transform}"' if transform else ""
    paths = SIMPLE_MARK_PATHS.replace("<path ", f'<path fill="{fill}" ')
    return f"  <g{attr}>\n    {paths.replace(chr(10), chr(10) + '    ')}\n  </g>"


def wordmark(text: str, fill: str, *, x: float, y: float, size: float) -> str:
    return (
        f'  <text x="{x}" y="{y}" fill="{fill}" '
        'font-family="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" '
        f'font-size="{size}" font-weight="600" letter-spacing="-2">{text}</text>'
    )


def horizontal(text_fill: str, *, mono: bool = False) -> str:
    mark = mono_mark_group(text_fill, "translate(20 20)") if mono else mark_group("translate(20 20)")
    return svg(
        "0 0 612 160",
        f"{mark}\n{wordmark('Kestrel', text_fill, x=184, y=109, size=76)}",
        "Kestrel",
        width=612,
        height=160,
    )


def stacked(text_fill: str) -> str:
    return svg(
        "0 0 420 350",
        f"{mark_group('translate(142 30)')}\n{wordmark('Kestrel', text_fill, x=68, y=292, size=74)}",
        "Kestrel",
        width=420,
        height=350,
    )


def mark_color() -> str:
    return svg("0 0 144 144", mark_group("translate(4 6)"), "Kestrel mark", width=144, height=144)


def mark_mono(fill: str, title: str) -> str:
    return svg(
        "0 0 144 144",
        mono_mark_group(fill, "translate(4 6)"),
        title,
        width=144,
        height=144,
    )


def mark_outline() -> str:
    paths = SIMPLE_MARK_PATHS.replace(
        "<path ",
        f'<path fill="none" stroke="{VIOLET}" stroke-width="3" stroke-linejoin="round" ',
    )
    return svg(
        "0 0 144 144",
        f'  <g transform="translate(4 6)">\n    {paths.replace(chr(10), chr(10) + "    ")}\n  </g>',
        "Kestrel outline mark",
        width=144,
        height=144,
    )


def wordmark_only(fill: str) -> str:
    return svg(
        "0 0 440 120",
        wordmark("Kestrel", fill, x=10, y=88, size=92),
        "Kestrel",
        width=440,
        height=120,
    )


def app_icon(background: str) -> str:
    dark = background == DARK_SLATE
    background_fill = "url(#app-background)" if dark else background
    background_defs = (
        f"""  <defs>
    <radialGradient id="app-background" cx="0" cy="0" r="1" gradientTransform="translate(220 170) rotate(43) scale(900)">
      <stop stop-color="#15104A"/>
      <stop offset=".55" stop-color="#090C24"/>
      <stop offset="1" stop-color="{DARK_SLATE}"/>
    </radialGradient>
  </defs>
"""
        if dark
        else ""
    )
    return svg(
        "0 0 1024 1024",
        f'{background_defs}  <rect x="2" y="2" width="1020" height="1020" rx="220" '
        f'fill="{background_fill}" stroke="{"#272351" if dark else "#E2E8F0"}" stroke-width="4"/>\n'
        f"{mark_group('translate(180 210) scale(4.9)')}",
        "Kestrel app icon",
        width=1024,
        height=1024,
    )


def favicon(*, mono: str | None = None) -> str:
    mark = mono_mark_group(mono, "translate(5 7) scale(.4)") if mono else mark_group("translate(5 7) scale(.4)")
    return svg("0 0 64 64", mark, "Kestrel favicon", width=64, height=64)


def small_mark() -> str:
    return svg(
        "0 0 24 24",
        mark_group("translate(.8 1.2) scale(.165)"),
        "Kestrel small mark",
        width=24,
        height=24,
    )


def social_card(*, light: bool) -> str:
    background = WHITE if light else INK
    text = INK if light else WHITE
    grid = "#CBD5E1" if light else "#2A3140"
    return svg(
        "0 0 1200 630",
        f"""  <rect width="1200" height="630" fill="{background}"/>
  <defs>
    <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">
      <path d="M48 0H0v48" fill="none" stroke="{grid}" stroke-opacity=".24"/>
    </pattern>
    <radialGradient id="glow" cx="0" cy="0" r="1" gradientTransform="translate(260 110) rotate(36) scale(650 420)" gradientUnits="userSpaceOnUse">
      <stop stop-color="{VIOLET}" stop-opacity=".26"/>
      <stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#grid)"/>
  <rect width="1200" height="630" fill="url(#glow)"/>
{mark_group("translate(92 142) scale(1.55)")}
{wordmark("Kestrel", text, x=330, y=288, size=116)}
  <text x="98" y="430" fill="{text}" font-family="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="52" font-weight="500" letter-spacing="-1.4">Open-source security for SaaS.</text>
  <text x="100" y="490" fill="{text}" fill-opacity=".58" font-family="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="25" font-weight="500">Posture · identity · access · evidence</text>""",
        "Kestrel — Open-source security for SaaS",
        width=1200,
        height=630,
    )


def social_square(*, light: bool) -> str:
    background = WHITE if light else INK
    text = INK if light else WHITE
    return svg(
        "0 0 1080 1080",
        f"""  <rect width="1080" height="1080" fill="{background}"/>
  <defs>
    <radialGradient id="square-glow" cx="0" cy="0" r="1" gradientTransform="translate(540 830) rotate(90) scale(500 740)" gradientUnits="userSpaceOnUse">
      <stop stop-color="{VIOLET}" stop-opacity="{".56" if not light else ".22"}"/>
      <stop offset=".54" stop-color="{PERIWINKLE}" stop-opacity="{".24" if not light else ".12"}"/>
      <stop offset="1" stop-color="{BLUE}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1080" height="1080" fill="url(#square-glow)"/>
{mark_group("translate(345 205) scale(3)")}
{wordmark("Kestrel", text, x=265, y=690, size=146)}
  <text x="540" y="785" text-anchor="middle" fill="{text}" fill-opacity=".72" font-family="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="38" font-weight="500">Open-source security for SaaS.</text>""",
        "Kestrel",
        width=1080,
        height=1080,
    )


def write(relative_path: str, contents: str) -> None:
    destination = BRAND_ASSETS / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(contents, encoding="utf-8")


def main() -> None:
    assets = {
        "logos/kestrel-logo-horizontal-dark.svg": horizontal(WHITE),
        "logos/kestrel-logo-horizontal-light.svg": horizontal(INK),
        "logos/kestrel-logo-horizontal-mono-white.svg": horizontal(WHITE, mono=True),
        "logos/kestrel-logo-horizontal-mono-dark.svg": horizontal(INK, mono=True),
        "logos/kestrel-logo-stacked-dark.svg": stacked(WHITE),
        "logos/kestrel-logo-stacked-light.svg": stacked(INK),
        "logos/kestrel-wordmark-dark.svg": wordmark_only(WHITE),
        "logos/kestrel-wordmark-light.svg": wordmark_only(INK),
        "logos/kestrel-mark-color.svg": mark_color(),
        "logos/kestrel-mark-simple-color.svg": mark_color(),
        "logos/kestrel-mark-white.svg": mark_mono(WHITE, "Kestrel white mark"),
        "logos/kestrel-mark-dark.svg": mark_mono(INK, "Kestrel dark mark"),
        "logos/kestrel-mark-outline.svg": mark_outline(),
        "icons/kestrel-app-icon-dark.svg": app_icon(DARK_SLATE),
        "icons/kestrel-app-icon-light.svg": app_icon(WHITE),
        "icons/kestrel-favicon.svg": favicon(),
        "icons/kestrel-favicon-white.svg": favicon(mono=WHITE),
        "icons/kestrel-favicon-dark.svg": favicon(mono=INK),
        "icons/kestrel-mark-small.svg": small_mark(),
        "social/kestrel-open-graph-dark.svg": social_card(light=False),
        "social/kestrel-open-graph-light.svg": social_card(light=True),
        "social/kestrel-social-square-dark.svg": social_square(light=False),
        "social/kestrel-social-square-light.svg": social_square(light=True),
    }

    for relative_path, contents in assets.items():
        write(relative_path, contents)

    WEB_BRAND.mkdir(parents=True, exist_ok=True)
    runtime_assets = {
        "kestrel-logo-horizontal-dark.svg": assets["logos/kestrel-logo-horizontal-dark.svg"],
        "kestrel-logo-horizontal-light.svg": assets["logos/kestrel-logo-horizontal-light.svg"],
        "kestrel-mark-color.svg": assets["logos/kestrel-mark-color.svg"],
        "kestrel-mark-simple-color.svg": assets["logos/kestrel-mark-simple-color.svg"],
        "kestrel-mark-white.svg": assets["logos/kestrel-mark-white.svg"],
        "kestrel-mark-dark.svg": assets["logos/kestrel-mark-dark.svg"],
        "kestrel-app-icon-dark.svg": assets["icons/kestrel-app-icon-dark.svg"],
        "kestrel-app-icon-light.svg": assets["icons/kestrel-app-icon-light.svg"],
        "kestrel-mark-small.svg": assets["icons/kestrel-mark-small.svg"],
        "kestrel-open-graph-dark.svg": assets["social/kestrel-open-graph-dark.svg"],
        "kestrel-open-graph-light.svg": assets["social/kestrel-open-graph-light.svg"],
        "kestrel-social-square-dark.svg": assets["social/kestrel-social-square-dark.svg"],
        "kestrel-social-square-light.svg": assets["social/kestrel-social-square-light.svg"],
    }
    for filename, contents in runtime_assets.items():
        (WEB_BRAND / filename).write_text(contents, encoding="utf-8")

    (ROOT / "apps" / "web" / "public" / "favicon.svg").write_text(assets["icons/kestrel-favicon.svg"], encoding="utf-8")


if __name__ == "__main__":
    main()
