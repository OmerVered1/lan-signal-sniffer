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


# Sizes a Windows shell actually asks for, and the format each must be in.
# Explorer renders a PNG-compressed entry reliably only at 256x256; at the
# smaller sizes - a taskbar, a desktop shortcut, a title bar - it wants a
# classic BMP and falls back to a generic icon when it does not get one.
# Pillow writes PNG for every size by default, which is why the shortcut showed
# a blank page while the app's own window icon looked right.
BMP_SIZES = (16, 24, 32, 48, 64, 128)
PNG_SIZE = 256


def write_ico(path: Path) -> None:
    """Write an .ico with BMP entries for the small sizes and PNG at 256.

    Assembled here rather than left to one `save` call because the two formats
    have to be mixed and Pillow chooses one for the whole file. A 256x256 BMP
    would work but costs a quarter of a megabyte on its own, and PNG at that
    size is what every Windows icon has used since Vista.
    """
    import io
    import struct

    entries = []
    for size in BMP_SIZES:
        buffer = io.BytesIO()
        draw(size).save(buffer, format="ICO", sizes=[(size, size)], bitmap_format="bmp")
        entries.append((size, _payload(buffer.getvalue())))
    buffer = io.BytesIO()
    draw(PNG_SIZE).save(buffer, format="PNG")
    entries.append((PNG_SIZE, buffer.getvalue()))

    offset = 6 + 16 * len(entries)
    directory, blobs = b"", b""
    for size, blob in entries:
        directory += struct.pack(
            "<BBBBHHII",
            0 if size >= 256 else size,
            0 if size >= 256 else size,
            0, 0, 1, 32, len(blob), offset,
        )
        blobs += blob
        offset += len(blob)
    path.write_bytes(struct.pack("<HHH", 0, 1, len(entries)) + directory + blobs)


def _payload(single: bytes) -> bytes:
    """The image bytes out of a one-entry .ico Pillow just wrote."""
    import struct

    size, offset = struct.unpack("<II", single[14:22])
    return single[offset : offset + size]


def main() -> None:
    png = HERE / "app_icon.png"
    draw(1024).save(png)

    write_ico(HERE / "app_icon.ico")

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
