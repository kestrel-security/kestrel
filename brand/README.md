# Kestrel Brand Package

Professional vector and raster assets based on the approved folded-bird Kestrel
lockup.

The package includes horizontal and stacked lockups, product and formal company
wordmarks, color/mono/outline bird marks, favicons, app icons, and dark/light
social cards. All SVGs use one canonical geometry and palette.

See `BRAND_GUIDELINES.md` for identity rules, `UI_STYLE_GUIDE.md` for
product/landing-page implementation guidance, and `docs/brand.md` for names
and technical identifiers. Third-party SaaS marks used in
Explore / findings: `THIRD_PARTY_MARKS.md`.

## In this repository

- Source of truth: this `brand/` directory (guidelines + full asset set).
- Runtime UI copies live under `apps/web/public/brand/` and `apps/web/public/favicon.svg`.
- `generate_assets.py` regenerates the SVG suite and synchronized web copies.
- `render_raster_assets.py` exports PNG/JPG/PDF/ICO deliverables and web copies.
- PNGs under `assets/raster/` are ready for surfaces that cannot consume SVG.
- Do not redraw logos; copy from `assets/` when adding surfaces.
