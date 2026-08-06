"""The identification step: the user names what the scan found.

The scan ranks candidates; it does not decide. Every row shows the evidence the
ranking was based on — the shape of the trace, the range of values, where in the
reply the bytes sit — and the reading can be swapped for any of the overlapping
alternatives the scan set aside. A row only reaches the profile if the user
ticks it and gives it a name.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..protocol.fields import Candidate, FieldScan, scan_channel
from ..protocol.framer import Channel, FlowAnalysis
from .live_view import sparkline

# Candidates offered per channel. Past the first few the scores fall away
# sharply, and a long list makes the real signals harder to pick out.
CANDIDATES_PER_CHANNEL = 6

COL_USE, COL_CHANNEL, COL_WHERE, COL_TRACE, COL_RANGE, COL_NAME, COL_UNIT, COL_SCALE, COL_BIAS = range(9)

# (name, unit, signature, mask, offset, encoding, scale, bias)
Selection = Tuple[str, str, bytes, List[bool], int, str, float, float]


class _Row:
    """One offered candidate and the widgets that let the user accept it."""

    def __init__(self, channel: Channel, candidate: Candidate) -> None:
        self.channel = channel
        self.candidate = candidate
        self.use = QCheckBox()
        self.name = QLineEdit()
        self.unit = QLineEdit()
        self.where = QComboBox()
        self.scale = QDoubleSpinBox()
        self.bias = QDoubleSpinBox()

        for box, default in ((self.scale, 1.0), (self.bias, 0.0)):
            box.setDecimals(6)
            box.setRange(-1e9, 1e9)
            box.setValue(default)
        self.scale.setToolTip(
            "Multiplies the raw value. Use it when a device reports in counts —\n"
            "a register holding 1503 for 150.3 degrees needs a scale of 0.1."
        )
        self.bias.setToolTip("Added after scaling, for offset units such as K vs degC.")

        self.where.addItem(candidate.describe(), (candidate.offset, candidate.encoding))
        for alt in candidate.alternatives:
            self.where.addItem(
                f"{alt.describe()}  (alternative)", (alt.offset, alt.encoding)
            )
        self.where.setToolTip(
            "Where in the reply this value was read from. The alternatives are\n"
            "other readings of the same bytes that scored lower."
        )

        self.name.setPlaceholderText("name this signal…")
        self.unit.setPlaceholderText("unit")
        self.use.stateChanged.connect(self._sync_enabled)
        self._sync_enabled()

    def _sync_enabled(self) -> None:
        on = self.use.isChecked()
        for widget in (self.name, self.unit, self.where, self.scale, self.bias):
            widget.setEnabled(on)

    def selection(self) -> Optional[Selection]:
        if not self.use.isChecked():
            return None
        offset, encoding = self.where.currentData()
        return (
            self.name.text().strip(),
            self.unit.text().strip(),
            self.channel.signature,
            list(self.channel.mask),
            offset,
            encoding,
            self.scale.value(),
            self.bias.value(),
        )


class IdentifyDialog(QDialog):
    """Presents every channel's ranked candidates for naming."""

    def __init__(self, analysis: FlowAnalysis, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Identify the signals")
        self.resize(1240, 640)
        self._analysis = analysis
        self._rows: List[_Row] = []

        layout = QVBoxLayout(self)
        layout.addWidget(self._summary_label())

        self._table = QTableWidget(self)
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels(
            ["Use", "Channel", "Read from", "Shape", "Range", "Name", "Unit",
             "Scale", "Offset"]
        )
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(COL_NAME, QHeaderView.Stretch)
        layout.addWidget(self._table, 1)

        self._populate()

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel, parent=self
        )
        buttons.button(QDialogButtonBox.Save).setText("Save profile")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ----- construction --------------------------------------------------

    def _summary_label(self) -> QWidget:
        spec = self._analysis.request_spec
        bits = [
            f"<b>{len(self._analysis.channels)}</b> channel(s) found",
            f"framing: {spec.describe() if spec else 'unknown'}",
            f"interaction: {self._analysis.interaction.replace('_', '/')}",
        ]
        text = " &nbsp;·&nbsp; ".join(bits)
        if self._analysis.warnings:
            text += "<br><span style='color:#a04000'>" + "<br>".join(
                self._analysis.warnings
            ) + "</span>"
        label = QLabel(text)
        label.setWordWrap(True)
        label.setTextFormat(Qt.RichText)
        return label

    def _populate(self) -> None:
        entries: List[Tuple[Channel, FieldScan]] = [
            (channel, scan_channel(channel.payloads))
            for channel in self._analysis.channels
        ]
        total = sum(
            min(CANDIDATES_PER_CHANNEL, len(scan.candidates)) for _c, scan in entries
        )
        self._table.setRowCount(total)

        row = 0
        for channel, scan in entries:
            for rank, candidate in enumerate(scan.candidates[:CANDIDATES_PER_CHANNEL]):
                widgets = _Row(channel, candidate)
                # Only the strongest candidate per channel starts ticked; the
                # rest are there to be promoted if the top pick is wrong.
                widgets.use.setChecked(rank == 0 and not candidate.is_constant)
                self._rows.append(widgets)

                self._table.setCellWidget(row, COL_USE, _centred(widgets.use))
                channel_cell = QTableWidgetItem(
                    channel.signature_hex if rank == 0 else ""
                )
                # The column is too narrow for a long signature, and this is the
                # value worth cross-referencing against a known command list.
                channel_cell.setToolTip(
                    f"request: {channel.signature_hex}\n"
                    f"{channel.count} replies, "
                    f"{channel.median_period() or 0:.2f} s apart"
                )
                self._table.setItem(row, COL_CHANNEL, channel_cell)
                self._table.setCellWidget(row, COL_WHERE, widgets.where)
                self._table.setCellWidget(
                    row, COL_TRACE, sparkline(candidate.preview)
                )
                self._table.setItem(row, COL_RANGE, QTableWidgetItem(
                    _range_text(candidate)
                ))
                self._table.setCellWidget(row, COL_NAME, widgets.name)
                self._table.setCellWidget(row, COL_UNIT, widgets.unit)
                self._table.setCellWidget(row, COL_SCALE, widgets.scale)
                self._table.setCellWidget(row, COL_BIAS, widgets.bias)
                self._table.setRowHeight(row, 40)
                row += 1

        # Explicit widths rather than resize-to-contents. Sizing to contents lets
        # the sparkline and the range text consume the full width and push Name
        # off the right edge — and Name is the one column the user has to fill
        # in, so it must be visible without scrolling.
        for column, width in (
            (COL_USE, 42),
            (COL_CHANNEL, 118),
            (COL_WHERE, 152),
            (COL_TRACE, 150),
            (COL_RANGE, 148),
            (COL_UNIT, 72),
            (COL_SCALE, 92),
            (COL_BIAS, 92),
        ):
            self._table.setColumnWidth(column, width)
        self._table.horizontalHeader().setSectionResizeMode(
            COL_NAME, QHeaderView.Stretch
        )

    # ----- result --------------------------------------------------------

    def selections(self) -> List[Selection]:
        return [s for s in (r.selection() for r in self._rows) if s is not None]

    def _on_accept(self) -> None:
        chosen = self.selections()
        if not chosen:
            QMessageBox.warning(
                self,
                "Nothing selected",
                "Tick at least one signal and give it a name before saving.",
            )
            return

        unnamed = [c for c in chosen if not c[0]]
        if unnamed:
            QMessageBox.warning(
                self,
                "Missing names",
                f"{len(unnamed)} selected signal(s) still need a name. The name "
                "becomes the CSV column heading.",
            )
            return

        names = [c[0] for c in chosen]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            QMessageBox.warning(
                self,
                "Duplicate names",
                "These names are used more than once, and each one has to be a "
                "distinct CSV column: " + ", ".join(duplicates),
            )
            return

        self.accept()


def _centred(widget: QWidget) -> QWidget:
    holder = QWidget()
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addStretch(1)
    layout.addWidget(widget)
    layout.addStretch(1)
    return holder


def _range_text(candidate: Candidate) -> str:
    if candidate.is_constant:
        return f"{candidate.latest:.6g} (constant)"
    note = " (counter)" if candidate.is_counter else ""
    return f"{candidate.minimum:.6g} … {candidate.maximum:.6g}{note}"
