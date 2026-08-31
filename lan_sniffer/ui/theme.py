"""Light and dark, for an app that sits on a lab PC all day.

Kept as one stylesheet rather than scattered through the widgets, so the two
looks stay in step: a colour set in one place and forgotten in another is how
a dark theme ends up with white boxes in it.

The chart is not styled from here. pyqtgraph draws with its own pens and knows
nothing about Qt stylesheets, so `LiveView.set_theme` handles it and this
handles everything around it.
"""

from __future__ import annotations

DARK = """
QWidget { background: #1b2430; color: #c8d2e0; }
QGroupBox {
    border: 1px solid #2c3a4d; border-radius: 4px;
    margin-top: 8px; padding-top: 6px;
}
QGroupBox::title { subcontrol-origin: margin; left: 8px; color: #8fa3bf; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit, QPlainTextEdit,
QAbstractItemView {
    background: #232f3e; color: #e2e8f0;
    border: 1px solid #35465c; border-radius: 3px; padding: 2px 4px;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {
    background: #202a37; color: #6b7a8f;
}
QPushButton {
    background: #2a3849; color: #dbe4f0;
    border: 1px solid #3a4c63; border-radius: 3px; padding: 4px 10px;
}
QPushButton:hover { background: #33455a; }
QPushButton:pressed { background: #223044; }
QPushButton:disabled { background: #222c39; color: #5d6b7d; border-color: #2b3746; }
QMenu { background: #232f3e; border: 1px solid #35465c; }
QMenu::item:selected { background: #33455a; }
QMenuBar { background: #1b2430; }
QMenuBar::item:selected { background: #2a3849; }
QHeaderView::section {
    background: #26333f; color: #b6c4d6; border: 1px solid #35465c; padding: 3px;
}
QTableWidget, QTableView { gridline-color: #2f3e4f; background: #1f2937; }
QScrollBar:vertical, QScrollBar:horizontal { background: #1b2430; }
QScrollBar::handle { background: #3a4c63; border-radius: 4px; }
QToolTip { background: #26333f; color: #e2e8f0; border: 1px solid #3a4c63; }
/* Deliberately no QCheckBox::indicator rule. Styling the indicator replaces
   Qt's tick with a plain box, and a checked signal then looks unchecked -
   which on this window means a curve that is drawn but appears turned off. */
QSplitter::handle { background: #2c3a4d; }
QStatusBar { color: #8fa3bf; }
"""

LIGHT = ""


def stylesheet(dark: bool) -> str:
    return DARK if dark else LIGHT


# The recording banner is drawn from these rather than from a literal, so it
# stays legible against either background.
def banner_style(dark: bool, recording: bool) -> str:
    if recording:
        background, colour = ("#17683a", "#eaffef") if dark else ("#1a7f37", "white")
    else:
        background, colour = ("#2a3849", "#93a4ba") if dark else ("#e8e8e8", "#555")
    return (
        f"background:{background}; color:{colour}; font-weight:bold; "
        "font-size:15px; padding:9px; border-radius:4px;"
    )


def readout(dark: bool) -> str:
    """The live value panel on a device card."""
    return (
        "font-size:11px; color:#c8d2e0;" if dark else "font-size:11px; color:#333;"
    )


def muted(dark: bool) -> str:
    """For the small explanatory lines under a control."""
    return "color:#8fa3bf; font-size:11px;" if dark else "color:#555; font-size:11px;"
