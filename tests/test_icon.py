"""The .ico Windows is handed.

This is checked because the failure is silent and looks like nothing at all.
Pillow writes every entry of an .ico as PNG by default; Windows renders a
PNG-compressed entry reliably only at 256x256, and at the sizes a taskbar and a
desktop shortcut actually ask for it falls back to a generic icon instead. The
file is valid, every tool reads it, and the shortcut shows a blank page.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

ICO = Path(__file__).resolve().parents[1] / "assets" / "app_icon.ico"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def entries():
    """(width, format) for every image in the icon."""
    data = ICO.read_bytes()
    count = struct.unpack("<H", data[4:6])[0]
    out = []
    for i in range(count):
        head = 6 + i * 16
        size, offset = struct.unpack("<II", data[head + 8 : head + 16])
        width = data[head] or 256
        kind = "png" if data[offset : offset + 8] == PNG_MAGIC else "bmp"
        out.append((width, kind))
    return out


def test_the_icon_exists_and_is_an_icon():
    assert ICO.exists(), "the app and installer specs both point at this file"
    assert ICO.read_bytes()[:4] == b"\x00\x00\x01\x00"


def test_the_sizes_a_shell_asks_for_are_all_present():
    widths = {width for width, _kind in entries()}
    for needed in (16, 32, 48, 256):
        assert needed in widths, f"{needed}px missing: {sorted(widths)}"


def test_the_small_sizes_are_bmp_because_windows_will_not_read_png_there():
    """The bug this guards: a taskbar icon that falls back to a blank page."""
    for width, kind in entries():
        if width < 256:
            assert kind == "bmp", f"{width}px is {kind}; Windows needs bmp below 256"


def test_the_largest_is_png_so_the_file_stays_a_sane_size():
    """A 256x256 BMP is a quarter of a megabyte on its own."""
    largest = [kind for width, kind in entries() if width == 256]
    assert largest == ["png"]
    assert ICO.stat().st_size < 200_000, ICO.stat().st_size


def test_pillow_can_still_read_every_size_back():
    Image = pytest.importorskip("PIL.Image")
    assert len(Image.open(ICO).info["sizes"]) == len(entries())
