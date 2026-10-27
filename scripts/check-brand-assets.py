#!/usr/bin/env python3
"""Regression checks for Kubidm's T1.1 branding; stdlib only."""
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def png_size(path: str) -> tuple[int, int]:
    payload = (ROOT / path).read_bytes()[:24]
    assert payload[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", payload[16:24])

def main() -> None:
    master = read("artwork/brand/mark.svg")
    assert master == read("server/core/static/img/logo-square.svg")
    assert master == read("server/core/static/img/logo.svg")
    assert "M 51 41 C 36 53 27 70 27 86" in master
    assert "M 55 127 Q 80 141 106 127" in master
    assert "M 109 41 C 125 53 132 71 130 86" in master
    assert "<image" not in master and "data:image" not in master
    assert read("artwork/brand/app-icon.svg") == read("server/core/static/img/favicon.svg")
    for path in [
        "artwork/brand/mark.svg", "artwork/brand/horizontal.svg",
        "artwork/brand/horizontal-dark.svg", "artwork/brand/stacked.svg",
        "artwork/brand/mark-mono-ink.svg", "artwork/brand/mark-mono-white.svg",
        "artwork/brand/app-icon.svg", "artwork/brand/social-preview.svg",
        "server/core/static/img/logo.svg", "server/core/static/img/logo-square.svg",
        "server/core/static/img/favicon.svg", "book/theme/favicon.svg",
    ]:
        ET.fromstring(read(path))
    for name, size in [
        ("favicon.png", 32), ("logo-180.png", 180),
        ("logo-192.png", 192), ("logo-256.png", 256), ("logo-512.png", 512),
        ("logo-192-maskable.png", 192), ("logo-512-maskable.png", 512),
    ]:
        assert png_size("server/core/static/img/" + name) == (size, size), name
    assert png_size("book/theme/favicon.png") == (32, 32)
    assert png_size("artwork/brand/social-preview.png") == (1280, 640)
    assert (ROOT / "server/core/static/img/logo.svg.br").exists()
    assert (ROOT / "server/core/static/img/logo-square.svg.br").exists()
    assert read("server/core/templates/base_icons.html").find("/pkg/img/favicon.svg") != -1
    manifest = read("server/core/src/https/manifest.rs")
    assert "256x156" not in manifest
    for icon in ("logo-192-maskable.png", "logo-512-maskable.png", "logo-256.png"):
        assert icon in manifest
    assert "artwork/brand/horizontal.svg" in read("README.md")
    assert "artwork/brand/horizontal.svg" in read("RELEASE_NOTES.md")
    assert "assets/kubidm-horizontal.svg" in read("pykubidm/docs/hooks/gen_files.py")
    for path in [
        "server/core/static/img/guide/kubidm-identity-glyph.svg",
        "server/core/static/img/guide/crab-idle.webp",
        "server/core/static/img/guide/crab-protect.webp",
    ]:
        assert (ROOT / path).exists(), path
    print("T1.1 brand assets and references: OK")

if __name__ == "__main__":
    main()
