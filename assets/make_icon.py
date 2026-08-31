#!/usr/bin/env python3
"""Draw the app icon, at every size the platforms ask for.

Kept as a script rather than as a pile of binaries nobody can edit: the icon is
generated, so changing it means changing a few numbers here and re-running,
which is easier to review than a replaced .ico.

The drawing is a waveform read off a wire — a signal being recovered from
traffic, which is what the app does. Two rules keep it legible at 16 px, where a
Windows taskbar and a browser tab will actually show it:

  * one shape, drawn thick. Detail below about 1/16th of the canvas disappears.
  * high contrast against both light and dark chrome, hence the dark plate.

    python assets/make_icon.py
"""

from __future__ import annotations

import math
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent

PLATE = (24, 32, 45, 255)        # deep slate, reads as "instrument"
TRACE = (78, 201, 245, 255)      # the recovered signal
TAP = (61, 220, 151, 255)        # where it is picked off the wire
WIRE = (86, 101, 124, 255)

# Rendered large and reduced, so the curve keeps its shape at small sizes.
SUPER = 8


def draw(size: int) -> Image.Image:
    n = size * SUPER
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    radius = int(n * 0.22)
    d.rounded_rectangle([0, 0, n - 1, n - 1], radius=radius, fill=PLATE)

    # The wire the signal is read from: a flat line across the lower third.
    wire_y = int(n * 0.76)
    inset = int(n * 0.16)
    d.line([inset, wire_y, n - inset, wire_y], fill=WIRE, width=max(1, int(n * 0.035)))

    # The waveform: one and a half cycles, decaying, so it reads as a real
    # measurement rather than as a logo's idea of a sine.
    points = []
    left, right = inset, n - inset
    mid = n * 0.44
    span = right - left
    for i in range(241):
        t = i / 240.0
        x = left + t * span
        envelope = 1.0 - 0.35 * t
        y = mid - math.sin(t * math.pi * 3.0) * n * 0.20 * envelope
        points.append((x, y))
    d.line(points, fill=TRACE, width=max(2, int(n * 0.075)), joint="curve")

    # The tap: where the trace meets the wire.
    r = int(n * 0.062)
    cx = left + span * 0.5
    d.ellipse([cx - r, wire_y - r, cx + r, wire_y + r], fill=TAP)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    png = HERE / "app_icon.png"
    draw(1024).save(png)

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    draw(256).save(
        HERE / "app_icon.ico",
        format="ICO",
        sizes=[(s, s) for s in ico_sizes],
    )

    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "app_icon.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            draw(size).save(iconset / f"icon_{size}x{size}.png")
            draw(size * 2).save(iconset / f"icon_{size}x{size}@2x.png")
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(HERE / "app_icon.icns")],
            check=True,
        )

    for name in ("app_icon.png", "app_icon.ico", "app_icon.icns"):
        path = HERE / name
        print(f"  {name:<16} {path.stat().st_size:>8,} bytes")


if __name__ == "__main__":
    main()
