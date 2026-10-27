#!/usr/bin/env python3
"""Rebuild checked-in Kubidm T1.1 PNG, ICO and preview assets.

Requires: python -m pip install cairosvg pillow
Run from any directory. Do not hand-edit generated PNGs.
"""
from pathlib import Path
import io
from PIL import Image
import cairosvg
import brotli

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "artwork/brand/app-icon.svg"
MARK = ROOT / "artwork/brand/mark.svg"
OUT = ROOT / "server/core/static/img"

def render(path: Path, size: int) -> Image.Image:
    raw = cairosvg.svg2png(bytestring=path.read_bytes(), output_width=size, output_height=size)
    return Image.open(io.BytesIO(raw)).convert("RGBA")

def write_png(image: Image.Image, destination: Path) -> None:
    # Indexed colour reduces git size while retaining a useful visual gradient.
    image.quantize(colors=32, method=Image.Quantize.FASTOCTREE,
                   dither=Image.Dither.NONE).save(destination, optimize=True)

for size in (32, 180, 192, 256, 512):
    write_png(render(SOURCE, size), OUT / f"logo-{size}.png")
write_png(render(SOURCE, 32), OUT / "favicon.png")
write_png(render(SOURCE, 32), ROOT / "book/theme/favicon.png")
for size in (192, 512):
    canvas = Image.new("RGBA", (size, size), "#F8F6F1")
    # All critical mark geometry stays inside the central 80% safe-zone diameter.
    symbol_size = round(size * .62)
    symbol = render(MARK, symbol_size)
    canvas.alpha_composite(symbol, ((size-symbol_size)//2, (size-symbol_size)//2))
    write_png(canvas, OUT / f"logo-{size}-maskable.png")
render(SOURCE, 32).save(OUT / "favicon.ico", format="ICO",
                        sizes=[(16, 16), (32, 32)])
print("T1.1 raster assets regenerated")

# Keep the precompressed static SVGs aligned with the canonical mark.
for name in ("logo.svg", "logo-square.svg"):
    svg_path = OUT / name
    (OUT / (name + ".br")).write_bytes(
        brotli.compress(svg_path.read_bytes(), quality=11)
    )

# Social preview: SVG is authoritative; generated PNG can be uploaded in
# GitHub repository settings as the social preview.
preview = ROOT / "artwork/brand/social-preview.svg"
preview_bytes = cairosvg.svg2png(
    bytestring=preview.read_bytes(), output_width=1280, output_height=640
)
preview_image = Image.open(io.BytesIO(preview_bytes)).convert("RGBA")
write_png(preview_image, ROOT / "artwork/brand/social-preview.png")
