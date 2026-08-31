#!/usr/bin/env python3
"""Launch the LAN Signal Sniffer.

    python main.py

Capture needs elevated rights: run as Administrator on Windows, or with sudo on
macOS and Linux. Without them the window still opens and explains what is
missing rather than failing silently — everything except live capture, including
re-decoding a saved session, works unprivileged.
"""

from __future__ import annotations

import sys
from pathlib import Path


def icon_path() -> Path | None:
    """Find the app icon, whether running from source or from a built bundle.

    PyInstaller unpacks bundled data to a temporary directory and points
    `sys._MEIPASS` at it, so the path next to this file is only right when
    running from a checkout.
    """
    bases = []
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        bases.append(Path(bundled))
    bases.append(Path(__file__).resolve().parent)
    for base in bases:
        for name in ("app_icon.png", "app_icon.ico"):
            candidate = base / "assets" / name
            if candidate.exists():
                return candidate
    return None


def main() -> int:
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication

    from lan_sniffer.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("LAN Signal Sniffer")
    found = icon_path()
    if found is not None:
        # Set on the application as well as the window: the taskbar and the
        # alt-tab list read the application's, not the window's.
        app.setWindowIcon(QIcon(str(found)))
    window = MainWindow()
    if found is not None:
        window.setWindowIcon(QIcon(str(found)))
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
