# Kestrel Brand Package

Professional vector and raster assets based on the approved folded-bird Kestrel
lockup.

The package includes horizontal and stacked lockups, wordmarks,
color/mono/outline bird marks, favicons, app icons, and dark/light social cards.
All SVGs use one canonical geometry and palette.

See `BRAND_GUIDELINES.md` for identity rules, `UI_STYLE_GUIDE.md` for
product/landing-page implementation guidance, and `docs/brand.md` for names
and technical identifiers. Third-party SaaS marks used in
Explore / findings: `THIRD_PARTY_MARKS.md`.

## In this repository

- Source of truth: this `brand/` directory (guidelines + full asset set).
- Runtime UI copies live under `apps/web/public/brand/` and `apps/web/public/favicon.svg`.
- `tokens.css` and `tokens.json` hold the color and gradient tokens; `tokens.json` also carries the name and tagline.
- `ASSET_PREVIEW.html` previews the main lockups and marks on one page; open it in a browser.
- `generate_assets.py` regenerates the SVG suite and synchronized web copies.
  Run it from the repository root: `python3 brand/generate_assets.py`.
- `render_raster_assets.py` exports PNG/JPG/PDF/ICO deliverables and web copies.
  It needs Google Chrome (or `CHROME_BIN`) and macOS `sips`.
- PNGs under `assets/raster/` are ready for surfaces that cannot consume SVG.
- Do not redraw logos; copy from `assets/` when adding surfaces.
