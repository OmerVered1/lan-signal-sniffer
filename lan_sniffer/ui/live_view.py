"""Live strip chart of the decoded signals.

Follows the plotting approach already used in
keithley-smu-control/realtime_tab.py: pyqtgraph, one curve per signal, a bounded
ring of recent points, and a redraw on a timer rather than on every sample.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Sequence

import pyqtgraph as pg
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QCheckBox, QGridLayout, QVBoxLayout, QWidget

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
        self._markers: List = []

        pg.setConfigOptions(antialias=True)
        self._plot = pg.PlotWidget()
        self._plot.setBackground("w")
        self._plot.showGrid(x=True, y=True, alpha=0.25)
        self._plot.setLabel("bottom", "Elapsed time", units="s")
        self._legend = self._plot.addLegend(offset=(-10, 10))

        # A grid rather than a row: two instruments can contribute a dozen or
        # more signals, and a single row of checkboxes runs off the window.
        self._legend_row = QGridLayout()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._plot, 1)
        layout.addLayout(self._legend_row)

    # ----- setup ---------------------------------------------------------

    def set_signals(self, names: Sequence[str], units: Dict[str, str]) -> None:
        """Reset the plot for a new profile, device list, or session.

        The old curves have to be taken off the plot, not merely emptied.
        Leaving them behind kept every previous name in the legend, so each
        relabel or added device stacked another set of entries on top of the
        last — with two devices the legend filled the chart.
        """
        self.clear()
        for curve in self._curves.values():
            self._plot.removeItem(curve)
        self._curves.clear()
        self._times.clear()
        self._values.clear()
        if self._legend is not None:
            self._legend.clear()

        while self._legend_row.count():
            item = self._legend_row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Unparent before scheduling deletion: deleteLater only takes
                # effect once the event loop runs, and until then the old
                # checkboxes keep painting over the chart.
                widget.setParent(None)
                widget.deleteLater()
        self._boxes.clear()

        columns = 5
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
            self._legend_row.addWidget(box, i // columns, i % columns)

    def clear(self) -> None:
        self._t0 = None
        for name in list(self._curves):
            self._times[name].clear()
            self._values[name].clear()
            self._curves[name].setData([], [])
        for marker in getattr(self, "_markers", []):
            self._plot.removeItem(marker)
        self._markers = []

    def mark_session(self, ts: float, kind: str) -> None:
        """Draw where a session opened or closed.

        Recording state is otherwise invisible on the trace: the plot looks
        identical whether or not anything is being written to disk. A line on
        the data itself is the one place the answer cannot be missed while
        watching the run.
        """
        if self._t0 is None:
            self._t0 = ts
        colour = "#1a7f37" if kind == "start" else "#a04000"
        line = pg.InfiniteLine(
            pos=ts - self._t0,
            angle=90,
            pen=pg.mkPen(colour, width=2, style=Qt.DashLine),
            label="REC start" if kind == "start" else "REC stop",
            labelOpts={"position": 0.92, "color": colour, "fill": "#ffffffc0"},
        )
        self._plot.addItem(line)
        if not hasattr(self, "_markers"):
            self._markers = []
        self._markers.append(line)

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
