# Kubidm visual identity — T1.1 Balanced

The **T1.1 Balanced** mark is the canonical Kubidm product identity. Its source of truth is [mark.svg](mark.svg), manually recreated from the approved T1.1 artwork; this is not a generic three-node network diagram.

## Components and usage

| Asset | Purpose |
| --- | --- |
| [mark.svg](mark.svg) | Canonical unframed symbol for the login UI, navbar, documentation and integrations |
| [horizontal.svg](horizontal.svg) | Primary signature for README, documentation and communications |
| [horizontal-dark.svg](horizontal-dark.svg) | Signature placed on dark surfaces |
| [stacked.svg](stacked.svg) | Tall-format artwork |
| [mark-mono-ink.svg](mark-mono-ink.svg) and [mark-mono-white.svg](mark-mono-white.svg) | Single-ink applications |
| [app-icon.svg](app-icon.svg) | Padded, opaque favicon / app icon |
| [social-preview.svg](social-preview.svg) | Vector source for GitHub social artwork |

Raster icons are exported and checked in under `server/core/static/img/`. For regeneration use `python scripts/render-brand-assets.py` from the repository root (requires Pillow and CairoSVG). Run `python scripts/check-brand-assets.py` to verify references and PNG sizes.

## Rules

- Preserve the exact three teal nodes with dark outlines, independent orange center, and *three separate curved arcs*. No straight spokes or outer shield.
- Never embed bitmaps in the master SVG.
- Do not use the illustrated crab as a substitute for the compact product mark. The crab remains a separate, unchanged mascot.
- Use the padded app icon for browser and PWA surfaces, the unframed mark for product branding.
- In the sign-in UI, tenant-uploaded logo images always take precedence over the fallback Kubidm symbol.
- Keep clear space around the symbol (at least one-quarter the diameter of a peripheral teal node).
- Before publishing third-party merchandise, review the brand's trademark and art license obligations.

## Working colors

- Dark navy ink: `#042D3A`
- Teal/arc: `#007E86` → `#005B6A`
- Teal/nodes: `#2BB2B6` → `#1696A0`
- Orange/center: `#FF8110` → `#F16B06`
- Warm off-white app surface: `#F8F6F1`

The typography in signature SVGs remains a font-family lockup, not outlined letterforms. Check rendering before external printing. The GitHub social-preview SVG is provided for export; GitHub's social-preview repository setting is configured manually.

## Provenance and licensing

These T1.1 assets are newly generated visual-brand artifacts. Historical artwork in `artwork/` is retained, **not relicensed** by this change. Historical artist credits and their CC-BY-NC-ND notice remain in `artwork/README.md`. The logo's adoption does not alter the ownership or licensing of those earlier works. Establish any separate license/trademark permissions for the new brand assets before external redistribution.
