# Kestrel Brand Guidelines

**Name:** Kestrel  
**Tagline:** Open-source security for SaaS.  
**Repository:** [`kestrel-security/kestrel`](https://github.com/kestrel-security/kestrel)

## Canonical mark
The SVGs in this package are the canonical production artwork. Every variant
is generated from the same measured two-path geometry in
`brand/generate_assets.py`, which is the single source of truth for the mark.

Defining features:
- broad diagonal folded wing/body
- separate compact head/upper wing
- sharp central negative-space notch
- violet-to-electric-blue gradient
- crisp angular facets with no decorative outline

Do not redraw or auto-trace this mark from screenshots.

## Naming
Use **Kestrel** everywhere: the product, the documentation, talks, and legal
notices. There is no separate formal name.

## Assets
- `assets/logos/kestrel-logo-horizontal-dark.svg`
- `assets/logos/kestrel-logo-horizontal-light.svg`
- `assets/logos/kestrel-logo-horizontal-mono-white.svg`
- `assets/logos/kestrel-logo-horizontal-mono-dark.svg`
- `assets/logos/kestrel-logo-stacked-dark.svg`
- `assets/logos/kestrel-logo-stacked-light.svg`
- `assets/logos/kestrel-wordmark-dark.svg`
- `assets/logos/kestrel-wordmark-light.svg`
- `assets/logos/kestrel-mark-color.svg`
- `assets/logos/kestrel-mark-simple-color.svg`
- `assets/logos/kestrel-mark-white.svg`
- `assets/logos/kestrel-mark-dark.svg`
- `assets/logos/kestrel-mark-outline.svg`
- `assets/icons/kestrel-app-icon-dark.svg`
- `assets/icons/kestrel-app-icon-light.svg`
- `assets/icons/kestrel-favicon.svg`
- `assets/icons/kestrel-favicon-white.svg`
- `assets/icons/kestrel-favicon-dark.svg`
- `assets/icons/kestrel-mark-small.svg`
- `assets/icons/kestrel-favicon.ico`
- `assets/social/kestrel-open-graph-dark.svg`
- `assets/social/kestrel-open-graph-light.svg`
- `assets/social/kestrel-social-square-dark.svg`
- `assets/social/kestrel-social-square-light.svg`
- `assets/raster/` — PNG exports for social metadata, app icons, and systems
  that cannot consume SVG
- `assets/print/kestrel-logo-horizontal.pdf` — portable print export

`dark` lockups are for dark backgrounds and use a light wordmark. `light`
lockups are for light backgrounds and use an ink wordmark.

## Logo rules
Preserve aspect ratio, geometry, and negative space. Use the color mark at
24px+, and the simplified monochrome favicon when color or detail is
constrained. Never stretch, recolor individual pieces, add shadows, rotate the
mark, or redraw the bird.

## Colors
Core palette:
- Violet `#7441F0`
- Periwinkle `#5D61F1`
- Blue `#4689ED`
- Dark Slate `#0F1117`
- Ink `#090C11`
- White `#F8FAFC`

The color mark uses the sampled Violet → Periwinkle → Blue gradient from the
approved icon. Do not flatten it to a single blue except in an explicit
monochrome context.

## Typography
Primary: **Inter**  
Code/CLI: **Geist Mono** or system monospace.

The logo wordmark uses Inter Semi Bold (`600`) with tight optical spacing.

## UI direction
Dark-first, technical, restrained, production-grade. Use subtle borders, minimal shadows, an 8px spacing grid, and monospace for code/policy/query surfaces.

Detailed component, color, typography, layout, and accessibility guidance:
[`UI_STYLE_GUIDE.md`](UI_STYLE_GUIDE.md).

## Landing page
Primary headline: **Open-source security for SaaS.**

Supporting copy: Kestrel gives security teams a programmable way to understand posture, identities, permissions, OAuth risk, and access across Okta, Google Workspace, GitHub, Slack, and custom SaaS applications.

## Voice
Direct, technical, concise, credible. Avoid generic cybersecurity hype.

## Accessibility
Maintain WCAG AA contrast, visible focus states, non-color-only severity indicators, and `prefers-reduced-motion`.

## Source of truth
Use these SVGs directly. Do not recreate the logo from screenshots. To
regenerate vector assets and synchronized copies under `apps/web/public`, run:

```bash
python3 brand/generate_assets.py
python3 brand/render_raster_assets.py
```
