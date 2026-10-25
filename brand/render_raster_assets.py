# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Render production raster/print exports from the canonical Kestrel SVGs.

Requires Google Chrome (or CHROME_BIN) and macOS `sips`. SVGs remain the source
of truth; these exports exist for app stores, social platforms, and legacy
clients that cannot consume SVG.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "brand" / "assets"
RASTER = ASSETS / "raster"
WEB_BRAND = ROOT / "apps" / "web" / "public" / "brand"
WEB_PUBLIC = ROOT / "apps" / "web" / "public"


def chrome_binary() -> Path:
    configured = os.environ.get("CHROME_BIN")
    candidates = [
        Path(configured) if configured else None,
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise RuntimeError("Google Chrome not found; set CHROME_BIN to a Chromium executable")


def render_svg(
    chrome: Path,
    source: Path,
    destination: Path,
    *,
    width: int,
    height: int,
    scale: float = 1,
    transparent: bool = False,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(chrome),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-sandbox",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=500",
        f"--force-device-scale-factor={scale}",
        f"--window-size={width},{height}",
        f"--screenshot={destination}",
    ]
    if transparent:
        command.append("--default-background-color=00000000")
    command.append(source.resolve().as_uri())
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def resize(source: Path, destination: Path, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["sips", "-z", str(size), str(size), str(source), "--out", str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def convert(source: Path, destination: Path, file_format: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["sips", "-s", "format", file_format, str(source), "--out", str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> None:
    chrome = chrome_binary()
    logos = ASSETS / "logos"
    icons = ASSETS / "icons"
    social = ASSETS / "social"

    render_svg(
        chrome,
        logos / "kestrel-logo-horizontal-dark.svg",
        RASTER / "kestrel-logo-horizontal-dark.png",
        width=612,
        height=160,
        scale=2,
        transparent=True,
    )
    render_svg(
        chrome,
        logos / "kestrel-logo-horizontal-light.svg",
        RASTER / "kestrel-logo-horizontal-light.png",
        width=612,
        height=160,
        scale=2,
        transparent=True,
    )
    render_svg(
        chrome,
        logos / "kestrel-mark-color.svg",
        RASTER / "kestrel-mark-color.png",
        width=144,
        height=144,
        scale=3.5555556,
        transparent=True,
    )

    app_dark_1024 = RASTER / "icons" / "kestrel-app-icon-dark-1024.png"
    app_light_1024 = RASTER / "icons" / "kestrel-app-icon-light-1024.png"
    render_svg(
        chrome,
        icons / "kestrel-app-icon-dark.svg",
        app_dark_1024,
        width=1024,
        height=1024,
    )
    render_svg(
        chrome,
        icons / "kestrel-app-icon-light.svg",
        app_light_1024,
        width=1024,
        height=1024,
    )

    for theme, source in (("dark", app_dark_1024), ("light", app_light_1024)):
        for size in (512, 256):
            resize(source, RASTER / "icons" / f"kestrel-app-icon-{theme}-{size}.png", size)
        for size in (512, 180, 32, 16):
            resize(source, RASTER / "favicons" / theme / f"kestrel-favicon-{size}.png", size)

    shutil.copy2(
        RASTER / "icons" / "kestrel-app-icon-dark-512.png",
        RASTER / "kestrel-app-icon-dark.png",
    )
    shutil.copy2(
        RASTER / "icons" / "kestrel-app-icon-light-512.png",
        RASTER / "kestrel-app-icon-light.png",
    )

    for theme in ("dark", "light"):
        render_svg(
            chrome,
            social / f"kestrel-open-graph-{theme}.svg",
            RASTER / f"kestrel-open-graph-{theme}.png",
            width=1200,
            height=630,
        )
        render_svg(
            chrome,
            social / f"kestrel-social-square-{theme}.svg",
            RASTER / f"kestrel-social-square-{theme}.png",
            width=1080,
            height=1080,
        )
        convert(
            RASTER / f"kestrel-open-graph-{theme}.png",
            RASTER / f"kestrel-open-graph-{theme}.jpg",
            "jpeg",
        )

    convert(
        RASTER / "favicons" / "dark" / "kestrel-favicon-32.png",
        ASSETS / "icons" / "kestrel-favicon.ico",
        "ico",
    )
    convert(
        RASTER / "kestrel-logo-horizontal-light.png",
        ASSETS / "print" / "kestrel-logo-horizontal.pdf",
        "pdf",
    )

    WEB_BRAND.mkdir(parents=True, exist_ok=True)
    public_copies = {
        RASTER / "icons" / "kestrel-app-icon-dark-512.png": WEB_BRAND / "kestrel-app-icon-dark.png",
        RASTER / "icons" / "kestrel-app-icon-light-512.png": WEB_BRAND / "kestrel-app-icon-light.png",
        RASTER / "kestrel-logo-horizontal-dark.png": WEB_BRAND / "kestrel-logo-horizontal-dark.png",
        RASTER / "kestrel-logo-horizontal-light.png": WEB_BRAND / "kestrel-logo-horizontal-light.png",
        RASTER / "kestrel-open-graph-dark.png": WEB_BRAND / "kestrel-open-graph-dark.png",
        RASTER / "kestrel-social-square-dark.png": WEB_BRAND / "kestrel-social-square-dark.png",
        ASSETS / "icons" / "kestrel-favicon.ico": WEB_PUBLIC / "favicon.ico",
    }
    for source, destination in public_copies.items():
        shutil.copy2(source, destination)


if __name__ == "__main__":
    main()
