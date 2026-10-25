# Kestrel UI Style Guide

This guide translates the Kestrel identity into repeatable product and landing
page decisions. `BRAND_GUIDELINES.md` governs logo artwork; this document
governs interface use.

## Brand character

Kestrel should feel:

- precise, technical, and credible
- dark-first without becoming visually heavy
- calm and evidence-led rather than alarmist
- modern, but not decorative or trend-dependent

Use visual intensity to explain hierarchy and risk. Do not use glow, gradients,
or motion merely to fill space.

## Logo selection

- **Product navigation:** horizontal dark lockup at 32–40px tall.
- **Light marketing header:** horizontal light lockup at 32–44px tall.
- **Compact navigation or mobile:** color mark at 24px or larger.
- **16–24px UI placement:** `kestrel-mark-small.svg`.
- **App launcher / touch icon:** dark app icon by default; light app icon only
  where the operating system supplies a light tile.
- **Monochrome surfaces:** use the white or ink mark. Never recolor one part of
  the bird.

Minimum sizes:

- horizontal lockup: 120px wide
- standalone color mark: 24px
- optimized small mark: 16px
- app icon: 32px

Clear space around a logo must be at least the height of the small head facet
on every side. Do not place borders, labels, or controls inside that space.

## Color system

### Brand colors

- Violet `#7441F0` — primary action, focus, leading edge of the mark
- Periwinkle `#5D61F1` — center transition and supporting accent
- Blue `#4689ED` — endpoint of the mark gradient and data emphasis
- Ink `#090C11` — primary dark canvas
- Dark slate `#0F1117` — app icon and elevated dark surface
- White `#F8FAFC` — primary light text and light canvas

Canonical brand gradient:

```css
linear-gradient(135deg, #7441F0 0%, #5D61F1 52%, #4689ED 100%)
```

Use the full gradient only for:

- the Kestrel mark
- restrained hero or social artwork
- a thin active/selected accent where a solid color is insufficient

Do not use the gradient as body text, long borders, table backgrounds, or every
primary button. Product controls should usually use solid Violet.

### Product neutrals

- App background: `#090C11`
- Surface: `#151922`
- Elevated surface: `#1B2130`
- Border: `#2A3140`
- Muted text: `#94A3B8`
- Primary text: `#F8FAFC`

### Semantic colors

Brand colors do not replace security semantics. Product UI uses **muted tone tokens**
(`--tone-*` in `globals.css`, exposed as `tone-*` Tailwind utilities) rather than
saturated Tailwind-500 palette classes:

- Critical: `--tone-critical` (desaturated coral red)
- High: `--tone-high` (warm burnt orange)
- Medium / warning: `--tone-medium` (muted gold)
- Low / informational: `--tone-low`, `--tone-info`
- Success: `--tone-success` (soft sage green)
- Neutral: `--tone-neutral` (muted slate)

Apply tones as **small accents** — left rail, icon, chart segment, status dot — on
**neutral text** with a low-opacity tinted fill (`bg-tone-*/10`, `border-tone-*/25`).
Do not paint large blocks or KPI values in full saturation.

Always pair semantic color with a label, icon, or shape. Never encode finding
severity through color alone.

## Typography

- **Logo wordmark:** Inter Semi Bold (`600`), tightly spaced. Use the supplied
  asset instead of recreating it in application code.
- **UI and marketing:** Inter.
- **Code, policy, identifiers, evidence values:** JetBrains Mono.

Recommended hierarchy:

- Landing hero: 48–72px, `600`, tight tracking
- Page title: 24–32px, `600`
- Section title: 16–20px, `600`
- Body/UI: 14–16px, `400`
- Label/metadata: 12–13px, `500`
- Code/evidence: 12–14px, mono

Use sentence case. Avoid all caps except short overlines or compact technical
labels; keep those under 20 characters and add letter spacing.

## Layout and shape

- Base spacing unit: 4px; prefer multiples of 8px for layout.
- Product panel radius: 8px.
- Marketing card radius: 12–16px.
- App icon radius: approximately 21.5% of icon size.
- Borders: 1px, low contrast.
- Shadows: minimal; use surface and border contrast before shadow.

Dense security data should remain scan-friendly. Prefer aligned labels,
consistent columns, compact metadata, and progressive disclosure over oversized
cards.

## Components

### Buttons

- Primary: solid Violet with white text.
- Secondary: elevated surface with a visible border.
- Destructive: semantic red, never the brand gradient.
- Focus: 2px Violet ring with sufficient offset and contrast.

### Cards and panels

Use Surface for cards and Elevated Surface for selected or nested content.
Reserve gradient glow for empty states, onboarding, login, and marketing hero
regions. Do not put glow behind dense tables or evidence.

### Navigation

The full lockup appears once in the primary shell. Active destinations use a
subtle Violet tint and border/ring; inactive destinations remain neutral.
Repeated bird icons in every navigation row weaken the identity.

The primary nav rail is collapsible: **expanded** (256px) shows the horizontal
dark lockup and destination labels; **collapsed** (64px icon rail) swaps to the
white mark at 24px or larger and hides labels (icon + tooltip + `aria-label`).
Collapse preference is per device in `localStorage`
(`kestrel-sidebar-collapsed`), applied before paint via a blocking script — the
same pattern as appearance. It is not stored on the operator record. Sidebar
tokens remain limited to `components/nav.tsx` and `components/theme-toggle.tsx`.

### Data visualization

Use Violet → Periwinkle → Blue for ordered product data, paths, or selected graph
relationships. Use tone tokens for severity and health. Provide legends and
text alternatives.

**Dashboard charts** (`apps/web/src/lib/chart-colors.ts`):

- **Severity** — `fill-tone-critical|high|medium|low|info` on bar/pie segments.
- **Finding status** — brand-forward: open `fill-primary`, resolved `fill-tone-success`,
  suppressed `fill-tone-neutral`, exception `fill-tone-info`, muted `fill-tone-low`.
- **Health** — `fill-tone-success|critical|medium|neutral|info`.
- **Generic series** — violet → periwinkle → blue cycle via `fill-primary` and tone tokens.

Charts fill their widget card (no fixed pixel height in the grid). Categorical
bars are horizontal with thin segments (`maxBarSize` 18); pie legends wrap in HTML below the plot.

**Badges and KPI tiles** — tinted fill + `text-foreground` label + tone-colored icon or dot.
KPI values stay neutral; only the left rail and icon carry hue.

### Motion

Motion should clarify state changes, graph traversal, or panel transitions.
Keep product transitions between 120–200ms and honor
`prefers-reduced-motion`. Never animate the logo continuously.

## Dark and light themes

Dark is the primary Kestrel presentation. Light mode is a complete theme, not
an inverted dark screenshot:

- use the light lockup (ink wordmark) on light surfaces
- keep the color mark unchanged
- use Ink for primary text and white for cards
- reduce glow opacity by at least half
- preserve semantic contrast and visible borders

In the product shell, appearance is **Light / System / Dark** in the sidebar
footer (default **System**, following `prefers-color-scheme`). Preference is
stored per device in `localStorage`, not on the operator record.

## Accessibility

- Meet WCAG AA contrast for text and controls.
- Keep focus states visible in both themes.
- Give standalone logo images an accessible name; decorative duplicates use an
  empty alt value.
- Do not place text inside raster logo artwork.
- Test the 16px favicon and 24px mark at 1× scale.
- Honor reduced motion and avoid flashing gradient effects.

### Surface layering

Beyond the base `background` / `card` pair, the product token set distinguishes
two more surface roles so the shell reads as structure rather than a stack of
identical cards:

- **`elevated`** (`bg-elevated` / `text-elevated-foreground`) — nested or
  selected content that floats above a card: dialogs, dropdown menus,
  popovers, select content, the command palette, a selected/expanded row, an
  inspector panel over a canvas. `popover` maps to this tone, so any Radix
  primitive built on `bg-popover` gets it automatically.
- **`sidebar`** (`bg-sidebar` / `text-sidebar-foreground`, plus
  `sidebar-border` / `sidebar-muted`) — the primary nav rail only. It is a
  fixed dark-slate tone in **both** themes (a deliberate persistent dark
  chrome rail, common in operator tools), distinct from `card`/`background` so
  the shell has visible depth even though content surfaces stay theme-correct.
  Nothing outside `components/nav.tsx` and `components/theme-toggle.tsx`
  should use these tokens.
- **`chart-grid`** — a low-contrast line color for chart gridlines/axes
  (recharts `<CartesianGrid>` and similar), tuned per theme instead of reusing
  `border`.
- **`tone-*`** — seven muted semantic hues (`critical`, `high`, `medium`, `low`,
  `info`, `success`, `neutral`) defined as HSL triplets in `:root` and `.dark`.
  Use for dashboard charts, severity/status badges, KPI accents, and callouts.
  Light and dark values are tuned independently for card contrast.

Use `.text-eyebrow` (a `@layer utilities` class in `globals.css`) for compact
uppercase micro-labels — KPI labels, section/legend headers, category tags —
instead of hand-rolling `text-xs font-medium uppercase tracking-wide` per
call site.

`PageHeader` (`apps/web/src/components/ui/page-header.tsx`) additionally
accepts optional `eyebrow` (small label above the title) and `status`
(a ReactNode, e.g. a badge, rendered inline next to the title) alongside the
original `title` / `description` / `actions` / `children`.

## Product component kit

The web app uses **shadcn/ui + Radix** under `apps/web/src/components/ui/`,
wired to these tokens (`darkMode: class`, dark-first).

Prefer shared primitives over one-off Tailwind:

| Use | Component |
|-----|-----------|
| Primary / secondary / destructive actions | `Button` |
| Forms | `Input`, `Textarea`, `Select`, `Checkbox`, `Switch`, `Label` |
| Panels | `Card` (+ Header / Content / Footer) |
| Ops lists | `Table` |
| Severity / status | `SeverityBadge` / `StatusBadge` (icon + label) |
| Filters | `FilterChip` |
| Page chrome | `PageHeader` |
| Empty | `EmptyState` (mark + title + hint + CTA) |
| Overlays | `Dialog`, `DropdownMenu`, `Tooltip`, `Tabs` |

Do not invent alternate button colors. Do not put brand gradient on primary
buttons or dense tables.

### Density and empty states

- List pages: `PageHeader` + bordered `Table` inside `Card`; filter rows use
  `FilterChip` (active = violet tint border, not glow).
- Empty lists: always include a next-step CTA when a destination exists
  (Add integration, Browse packs, Clear filters, Open Integrations).
- Exploration canvases may be full-bleed; list pages keep a stable max-width
  rhythm via the app shell.

## Implementation source of truth

- Palette: `brand/tokens.css` and `brand/tokens.json`
- Product mapping: `apps/web/src/app/globals.css`
- UI kit: `apps/web/src/components/ui/`
- Vector generator: `brand/generate_assets.py`
- Raster/print exporter: `brand/render_raster_assets.py`
- Canonical assets: `brand/assets/`
- Runtime copies: `apps/web/public/brand/`

After changing canonical geometry or color:

```bash
python3 brand/generate_assets.py
python3 brand/render_raster_assets.py
```
