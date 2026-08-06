"""Live strip chart of the decoded signals.

Follows the plotting approach already used in
keithley-smu-control/realtime_tab.py: pyqtgraph, one curve per signal, a bounded
ring of recent points, and a redraw on a timer rather than on every sample.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Sequence

import pyqtgraph as pg
from PyQt5.QtWidgets import QCheckBox, QHBoxLayout, QVBoxLayout, QWidget

# Points kept per signal. At one sample a second this is a bit over two hours,
# which is longer than anyone watches a plot; the CSV holds the full record.
MAX_POINTS = 8000

CURVE_COLOURS = (
    "#1f77b4",
    "#d62728",
    "#2ca02c",
    "#ff7f0e",
    "#9467bd",
    "#8c564b",
    "#17becf",
)


class LiveView(QWidget):
    """Plots decoded signals against elapsed time.

    Signals rarely share a scale — heat flow in milliwatts next to temperature
    in degrees would flatten one of them — so each curve can be shown or hidden
    individually rather than forcing them onto one axis.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._t0 = None
        self._times: Dict[str, Deque[float]] = {}
        self._values: Dict[str, Deque[float]] = {}
        self._curves: Dict[str, pg.PlotDataItem] = {}
        self._boxes: Dict[str, QCheckBox] = {}

        pg.setConfigOptions(antialias=True)
        self._plot = pg.PlotWidget()
        self._plot.setBackground("w")
        self._plot.showGrid(x=True, y=True, alpha=0.25)
        self._plot.setLabel("bottom", "Elapsed time", units="s")
        self._plot.addLegend(offset=(-10, 10))

        self._legend_row = QHBoxLayout()
        self._legend_row.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._plot, 1)
        layout.addLayout(self._legend_row)

    # ----- setup ---------------------------------------------------------

    def set_signals(self, names: Sequence[str], units: Dict[str, str]) -> None:
        """Reset the plot for a new profile or session."""
        self.clear()
        while self._legend_row.count() > 1:
            item = self._legend_row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        for i, name in enumerate(names):
            colour = CURVE_COLOURS[i % len(CURVE_COLOURS)]
            unit = units.get(name, "")
            label = f"{name} ({unit})" if unit else name
            self._times[name] = deque(maxlen=MAX_POINTS)
            self._values[name] = deque(maxlen=MAX_POINTS)
            self._curves[name] = self._plot.plot(
                [], [], pen=pg.mkPen(colour, width=2), name=label
            )
            box = QCheckBox(label)
            box.setChecked(True)
            box.setStyleSheet(f"color: {colour};")
            box.stateChanged.connect(self._apply_visibility)
            self._boxes[name] = box
            self._legend_row.insertWidget(self._legend_row.count() - 1, box)

    def clear(self) -> None:
        self._t0 = None
        for name in list(self._curves):
            self._times[name].clear()
            self._values[name].clear()
            self._curves[name].setData([], [])

    # ----- data ----------------------------------------------------------

    def add(self, ts: float, values: Dict[str, float]) -> None:
        if self._t0 is None:
            self._t0 = ts
        elapsed = ts - self._t0
        for name, value in values.items():
            if name in self._times:
                self._times[name].append(elapsed)
                self._values[name].append(value)

    def redraw(self) -> None:
        """Push buffered points to the curves. Called on a timer, not per sample."""
        for name, curve in self._curves.items():
            if self._boxes[name].isChecked() and self._times[name]:
                curve.setData(list(self._times[name]), list(self._values[name]))

    def _apply_visibility(self) -> None:
        for name, curve in self._curves.items():
            visible = self._boxes[name].isChecked()
            curve.setVisible(visible)
            if visible:
                curve.setData(list(self._times[name]), list(self._values[name]))


def sparkline(values: Sequence[float], colour: str = "#1f77b4") -> pg.PlotWidget:
    """A small, axis-free preview of one candidate's time series.

    Shape is what identifies a signal in the wizard — a drifting temperature
    looks nothing like a status byte — so these are drawn without axes or
    interaction to keep attention on the trace.
    """
    widget = pg.PlotWidget()
    widget.setBackground("w")
    widget.setMenuEnabled(False)
    widget.setMouseEnabled(x=False, y=False)
    widget.hideAxis("bottom")
    widget.hideAxis("left")
    widget.setFixedHeight(34)
    widget.setMinimumWidth(128)
    if values:
        widget.plot(range(len(values)), list(values), pen=pg.mkPen(colour, width=1.5))
    return widget
