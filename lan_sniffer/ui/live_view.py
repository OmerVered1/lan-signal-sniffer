"""Live strip chart of the decoded signals.

One instrument's signals do not share a scale, and two instruments certainly do
not. A coupled rig feeds this heat flow at 20,287 µV, a gas pressure at 1,600
mBar, temperatures reaching 1,000 °C, percentages, flows around 20 ml/min, and
mass concentrations of a hundredth of a percent. Drawn on one linear axis the
largest number sets the scale and everything else is a flat line along the
bottom - the chart is then not merely cluttered, it cannot show what is being
recorded.

So curves are grouped by unit into stacked panels sharing one time axis. Each
panel scales to its own quantity, and reading five small charts that work beats
one large one that does not. Where magnitudes are not the point - comparing the
shape of a desorption peak against a temperature ramp - **Normalise** puts every
curve on one panel scaled to its own range.

Colours are keyed to the signal's name rather than to its position, so adding a
device or renaming one does not reshuffle every trace on the chart mid-run.
"""

from __future__ import annotations

import zlib
from collections import deque
from typing import Deque, Dict, List, Optional, Sequence, Tuple

import pyqtgraph as pg
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# Points kept per signal. At ten samples a second this is a bit over thirteen
# minutes of visible history; the CSV holds the full record either way.
MAX_POINTS = 8000

CURVE_COLOURS = (
    "#1f77b4",
    "#d62728",
    "#2ca02c",
    "#ff7f0e",
    "#9467bd",
    "#8c564b",
    "#17becf",
    "#bcbd22",
    "#e377c2",
)

# Panels beyond this and each is too short to read; the rest share the last one.
MAX_PANELS = 6


class Theme:
    """The few colours the chart needs, for each of the two looks."""

    def __init__(self, dark: bool) -> None:
        self.dark = dark
        self.background = "#1b2430" if dark else "w"
        self.foreground = "#c8d2e0" if dark else "#222222"
        self.grid = 0.35 if dark else 0.25
        self.marker_fill = "#1b2430c0" if dark else "#ffffffc0"


def colour_for(name: str) -> str:
    """A stable colour for a signal, from its name.

    Position would do, until a device is added or renamed and every trace on a
    running chart changes colour at once.
    """
    return CURVE_COLOURS[zlib.crc32(name.encode("utf-8")) % len(CURVE_COLOURS)]


def group_by_unit(
    names: Sequence[str], units: Dict[str, str]
) -> List[Tuple[str, List[str]]]:
    """Split signals into panels, one per unit, in first-seen order.

    Unitless signals share a panel of their own: they are usually raw counts or
    ratios, and they have no more claim on a temperature axis than anything
    else does.
    """
    groups: Dict[str, List[str]] = {}
    for name in names:
        groups.setdefault(units.get(name, "") or "unitless", []).append(name)
    ordered = list(groups.items())
    if len(ordered) <= MAX_PANELS:
        return ordered
    # Too many to read. Keep the largest groups and pool the remainder, which
    # is still better than one panel for everything.
    ordered.sort(key=lambda item: -len(item[1]))
    kept = ordered[: MAX_PANELS - 1]
    rest = [n for _u, members in ordered[MAX_PANELS - 1 :] for n in members]
    return kept + [("mixed", rest)]


class LiveView(QWidget):
    """Plots decoded signals against elapsed time, grouped by unit."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._t0: Optional[float] = None
        self._times: Dict[str, Deque[float]] = {}
        self._values: Dict[str, Deque[float]] = {}
        self._curves: Dict[str, pg.PlotDataItem] = {}
        self._boxes: Dict[str, QCheckBox] = {}
        self._panels: List[pg.PlotItem] = []
        self._marks: List[Tuple[float, str]] = []
        self._names: List[str] = []
        self._units: Dict[str, str] = {}
        self._theme = Theme(dark=False)

        pg.setConfigOptions(antialias=True)
        self._chart = pg.GraphicsLayoutWidget()
        self._chart.setBackground(self._theme.background)

        self._normalise = QCheckBox("Normalise")
        self._normalise.setToolTip(
            "Put every curve on one panel, each scaled to its own range.\n"
            "For comparing shapes when the magnitudes are not the point."
        )
        self._normalise.stateChanged.connect(self._rebuild)

        self._all = QPushButton("All")
        self._none = QPushButton("None")
        for button in (self._all, self._none):
            button.setMaximumWidth(56)
            button.setFlat(True)
        self._all.clicked.connect(lambda: self._set_all(True))
        self._none.clicked.connect(lambda: self._set_all(False))

        self._hint = QLabel("")
        self._hint.setStyleSheet("color:#888; font-size:11px;")

        controls = QHBoxLayout()
        controls.setContentsMargins(6, 0, 6, 0)
        controls.addWidget(self._normalise)
        controls.addWidget(self._all)
        controls.addWidget(self._none)
        controls.addWidget(self._hint, 1)

        self._legend_row = QGridLayout()
        self._legend_row.setContentsMargins(6, 0, 6, 4)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._chart, 1)
        layout.addLayout(controls)
        layout.addLayout(self._legend_row)

    # ----- appearance -----------------------------------------------------

    def set_theme(self, dark: bool) -> None:
        self._theme = Theme(dark)
        self._chart.setBackground(self._theme.background)
        self._rebuild()

    # ----- setup ----------------------------------------------------------

    def set_signals(self, names: Sequence[str], units: Dict[str, str]) -> None:
        """Reset the chart for a new profile, device list, or session."""
        self._names = list(names)
        self._units = dict(units)
        self._t0 = None
        self._marks = []
        self._times = {n: deque(maxlen=MAX_POINTS) for n in self._names}
        self._values = {n: deque(maxlen=MAX_POINTS) for n in self._names}
        self._build_checkboxes()
        self._rebuild()

    def _build_checkboxes(self) -> None:
        while self._legend_row.count():
            item = self._legend_row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Unparent before scheduling deletion: deleteLater only takes
                # effect once the event loop runs, and until then the old
                # checkboxes keep painting over the chart.
                widget.setParent(None)
                widget.deleteLater()
        keep = {n: box.isChecked() for n, box in self._boxes.items()}
        self._boxes = {}
        columns = 4
        for i, name in enumerate(self._names):
            unit = self._units.get(name, "")
            box = QCheckBox(f"{name} ({unit})" if unit else name)
            box.setChecked(keep.get(name, True))
            box.setStyleSheet(f"color: {colour_for(name)};")
            box.stateChanged.connect(self._apply_visibility)
            self._boxes[name] = box
            self._legend_row.addWidget(box, i // columns, i % columns)

    def _rebuild(self) -> None:
        """Lay the panels out again, after a theme, mode or signal change."""
        self._chart.clear()
        self._panels = []
        self._curves = {}
        if not self._names:
            self._hint.setText("")
            return

        normalised = self._normalise.isChecked()
        groups = (
            [("normalised (0-1)", list(self._names))]
            if normalised
            else group_by_unit(self._names, self._units)
        )

        first: Optional[pg.PlotItem] = None
        for row, (unit, members) in enumerate(groups):
            panel = self._chart.addPlot(row=row, col=0)
            panel.showGrid(x=True, y=True, alpha=self._theme.grid)
            panel.getAxis("left").setLabel(unit, color=self._theme.foreground)
            for side in ("left", "bottom"):
                axis = panel.getAxis(side)
                axis.setPen(self._theme.foreground)
                axis.setTextPen(self._theme.foreground)
            if first is None:
                first = panel
            else:
                # One time axis for all of them: panning or zooming any panel
                # moves the rest, which is the whole point of stacking them.
                panel.setXLink(first)
            if row < len(groups) - 1:
                panel.getAxis("bottom").setStyle(showValues=False)
            else:
                panel.setLabel("bottom", "Elapsed time", units="s")
            for name in members:
                self._curves[name] = panel.plot(
                    [], [], pen=pg.mkPen(colour_for(name), width=2)
                )
            self._panels.append(panel)

        self._hint.setText(
            "each curve scaled to its own range"
            if normalised
            else f"{len(groups)} panel(s), grouped by unit — one shared time axis"
        )
        for ts, kind in list(self._marks):
            self._draw_mark(ts, kind)
        self._apply_visibility()
        self.redraw()

    def clear(self) -> None:
        self._t0 = None
        self._marks = []
        for name in self._times:
            self._times[name].clear()
            self._values[name].clear()
        for curve in self._curves.values():
            curve.setData([], [])
        self._rebuild()

    def _set_all(self, on: bool) -> None:
        for box in self._boxes.values():
            box.setChecked(on)

    # ----- markers --------------------------------------------------------

    def mark_session(self, ts: float, kind: str) -> None:
        """Draw where a session opened or closed, on every panel.

        Recording state is otherwise invisible on the trace: the chart looks
        identical whether or not anything is being written to disk.
        """
        if self._t0 is None:
            self._t0 = ts
        self._marks.append((ts, kind))
        self._draw_mark(ts, kind)

    def _draw_mark(self, ts: float, kind: str) -> None:
        if self._t0 is None:
            return
        colour = "#1a7f37" if kind == "start" else "#a04000"
        for i, panel in enumerate(self._panels):
            line = pg.InfiniteLine(
                pos=ts - self._t0,
                angle=90,
                pen=pg.mkPen(colour, width=2, style=Qt.DashLine),
                # Only the top panel is labelled, or the same words repeat down
                # the whole chart.
                label=("REC start" if kind == "start" else "REC stop") if i == 0 else None,
                labelOpts={
                    "position": 0.92,
                    "color": colour,
                    "fill": self._theme.marker_fill,
                },
            )
            panel.addItem(line)

    # ----- data -----------------------------------------------------------

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
        normalised = self._normalise.isChecked()
        for name, curve in self._curves.items():
            box = self._boxes.get(name)
            if box is not None and not box.isChecked():
                continue
            times = self._times.get(name)
            if not times:
                continue
            values = list(self._values[name])
            if normalised:
                values = _to_unit_range(values)
            curve.setData(list(times), values)

    def _apply_visibility(self) -> None:
        for name, curve in self._curves.items():
            box = self._boxes.get(name)
            curve.setVisible(bool(box is None or box.isChecked()))
        self.redraw()


def _to_unit_range(values: List[float]) -> List[float]:
    """Scale a curve to 0-1 over its own range, for shape comparison.

    A curve that never moves sits in the middle rather than at nothing: its
    flatness is the fact worth seeing, and dividing by a zero span would put it
    somewhere arbitrary or nowhere at all.
    """
    low, high = min(values), max(values)
    span = high - low
    if span <= 0:
        return [0.5] * len(values)
    return [(v - low) / span for v in values]


def sparkline(
    values: Sequence[float], colour: str = "#1f77b4", dark: bool = False
) -> pg.PlotWidget:
    """A small, axis-free preview of one candidate's time series.

    Shape is what identifies a signal in the wizard — a drifting temperature
    looks nothing like a status byte — so these are drawn without axes or
    interaction to keep attention on the trace.
    """
    widget = pg.PlotWidget()
    widget.setBackground("#1b2430" if dark else "w")
    widget.setMenuEnabled(False)
    widget.setMouseEnabled(x=False, y=False)
    widget.hideAxis("bottom")
    widget.hideAxis("left")
    widget.setFixedHeight(34)
    widget.setMinimumWidth(128)
    if values:
        widget.plot(range(len(values)), list(values), pen=pg.mkPen(colour, width=1.5))
    return widget
