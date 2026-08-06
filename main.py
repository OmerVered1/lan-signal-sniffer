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


def main() -> int:
    from PyQt5.QtWidgets import QApplication

    from lan_sniffer.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("LAN Signal Sniffer")
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
