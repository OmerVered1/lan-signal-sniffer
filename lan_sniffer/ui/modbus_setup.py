"""Set up a device that is read rather than watched.

A Modbus device has no traffic to identify, so the wizard that finds signals in
captured replies does not apply. What it needs instead is the register map the
user configured in the vendor software, which only they can supply.

The dialog therefore leans on one thing: a **Test read** that connects and shows
what comes back. Register maps are easy to get subtly wrong — an address off by
one, a word order the other way round, the wrong framing — and every one of
those mistakes returns numbers rather than an error. Seeing the values next to
what the vendor software displays is the only real check.
"""

from __future__ import annotations

from typing import List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ..readers.modbus import FORMATS, ModbusClient, ModbusError, RegisterSpec

COL_NAME, COL_ADDRESS, COL_FORMAT, COL_UNIT, COL_SCALE, COL_VALUE = range(6)


class ModbusSetupDialog(QDialog):
    """Enter a register map, and prove it against the instrument."""

    def __init__(
        self,
        host: str = "",
        port: int = 502,
        registers: Optional[List[RegisterSpec]] = None,
        settings: Optional[dict] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Read a device over Modbus")
        self.resize(880, 520)
        settings = settings or {}

        intro = QLabel(
            "For an instrument whose software publishes its results in Modbus "
            "registers.<br>Enter the addresses configured there, then "
            "<b>Test read</b> and check the values against what that software "
            "shows."
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)

        self._host = QLineEdit(host)
        self._host.setPlaceholderText("172.16.0.1")
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(port or 502)
        self._unit = QSpinBox()
        self._unit.setRange(0, 247)
        self._unit.setValue(int(settings.get("unit", 1)))
        self._framing = QComboBox()
        self._framing.addItem("RTU over TCP (Questor5 'RTU-TCP')", "rtu_tcp")
        self._framing.addItem("Standard Modbus TCP", "tcp")
        index = self._framing.findData(settings.get("framing", "rtu_tcp"))
        self._framing.setCurrentIndex(max(0, index))
        self._interval = QDoubleSpinBox()
        self._interval.setRange(0.2, 600.0)
        self._interval.setDecimals(1)
        self._interval.setSuffix(" s")
        self._interval.setValue(float(settings.get("poll_interval_s", 2.0)))
        self._interval.setToolTip(
            "How often to ask. There is no point polling faster than the\n"
            "instrument updates — a process analyser reports every few seconds."
        )

        link = QGroupBox("Connection")
        form = QFormLayout(link)
        form.addRow("Address", self._host)
        form.addRow("Port", self._port)
        form.addRow("Unit id", self._unit)
        form.addRow("Framing", self._framing)
        form.addRow("Read every", self._interval)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Address", "Format", "Unit", "Scale", "Last read"]
        )
        self._table.horizontalHeader().setSectionResizeMode(
            COL_NAME, QHeaderView.Stretch
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        for spec in registers or []:
            self._append(spec)
        if not registers:
            self._append(RegisterSpec(name="", address=40000))

        add = QPushButton("Add register")
        remove = QPushButton("Remove selected")
        test = QPushButton("Test read")
        add.clicked.connect(lambda: self._append(RegisterSpec(name="", address=self._next_address())))
        remove.clicked.connect(self._remove_selected)
        test.clicked.connect(self._test_read)
        row = QHBoxLayout()
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch(1)
        row.addWidget(test)

        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.RichText)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel, self)
        buttons.button(QDialogButtonBox.Save).setText("Save profile")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(link)
        layout.addWidget(self._table, 1)
        layout.addLayout(row)
        layout.addWidget(self._status)
        layout.addWidget(buttons)

    # ----- the table ------------------------------------------------------

    def _next_address(self) -> int:
        specs = self.registers()
        if not specs:
            return 40000
        last = specs[-1]
        return last.address + last.registers

    def _append(self, spec: RegisterSpec) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        name = QLineEdit(spec.name)
        name.setPlaceholderText("e.g. V1_I_18")
        address = QSpinBox()
        address.setRange(0, 65535 * 2)
        address.setValue(spec.address)
        fmt = QComboBox()
        for option in FORMATS:
            fmt.addItem(option, option)
        fmt.setCurrentIndex(max(0, fmt.findData(spec.format)))
        fmt.setToolTip(
            "ieee754     — a 32-bit float across two registers. Prefer this.\n"
            "legacy_paired — Questor5's quotient/remainder pair.\n"
            "single      — one register scaled between limits, which this app\n"
            "              must then duplicate exactly or the values are wrong."
        )
        unit = QLineEdit(spec.unit)
        unit.setPlaceholderText("%")
        scale = QDoubleSpinBox()
        scale.setDecimals(6)
        scale.setRange(-1e9, 1e9)
        scale.setValue(spec.scale)

        for column, widget in (
            (COL_NAME, name),
            (COL_ADDRESS, address),
            (COL_FORMAT, fmt),
            (COL_UNIT, unit),
            (COL_SCALE, scale),
        ):
            self._table.setCellWidget(row, column, widget)
        self._table.setCellWidget(row, COL_VALUE, QLabel("—"))

    def _remove_selected(self) -> None:
        rows = sorted({i.row() for i in self._table.selectedIndexes()}, reverse=True)
        for row in rows:
            self._table.removeRow(row)

    def registers(self) -> List[RegisterSpec]:
        out: List[RegisterSpec] = []
        for row in range(self._table.rowCount()):
            name = self._table.cellWidget(row, COL_NAME).text().strip()
            if not name:
                continue
            out.append(
                RegisterSpec(
                    name=name,
                    address=self._table.cellWidget(row, COL_ADDRESS).value(),
                    format=self._table.cellWidget(row, COL_FORMAT).currentData(),
                    unit=self._table.cellWidget(row, COL_UNIT).text().strip(),
                    scale=self._table.cellWidget(row, COL_SCALE).value(),
                )
            )
        return out

    def settings(self) -> dict:
        return {
            "unit": self._unit.value(),
            "framing": self._framing.currentData(),
            "poll_interval_s": self._interval.value(),
        }

    @property
    def host(self) -> str:
        return self._host.text().strip()

    @property
    def port(self) -> int:
        return self._port.value()

    # ----- proving it -----------------------------------------------------

    def _test_read(self) -> None:
        specs = self.registers()
        if not self.host or not specs:
            self._status.setText(
                "<span style='color:#a04000'>Enter an address and at least one "
                "named register first.</span>"
            )
            return
        settings = self.settings()
        try:
            with ModbusClient(
                self.host,
                self.port,
                unit=settings["unit"],
                framing=settings["framing"],
                timeout=3.0,
            ) as client:
                values = client.read(specs)
        except ModbusError as e:
            self._status.setText(f"<span style='color:#a04000'>{e}</span>")
            return
        except OSError as e:
            self._status.setText(
                f"<span style='color:#a04000'>Could not reach "
                f"{self.host}:{self.port} — {e}<br>Check that the Modbus slave "
                "is enabled in the instrument's software and that the port "
                "matches.</span>"
            )
            return

        row_for = {}
        for row in range(self._table.rowCount()):
            widget = self._table.cellWidget(row, COL_NAME)
            if widget:
                row_for[widget.text().strip()] = row
        for name, value in values.items():
            row = row_for.get(name)
            if row is not None:
                self._table.setCellWidget(row, COL_VALUE, QLabel(f"{value:.6g}"))
        missing = [s.name for s in specs if s.name not in values]
        note = f"Read {len(values)} of {len(specs)} register(s)."
        if missing:
            note += " No value for: " + ", ".join(missing) + "."
        note += (
            "<br><b>Check these against the instrument's own display.</b> A "
            "wrong address or word order returns numbers, not an error."
        )
        self._status.setText(note)

    def _on_accept(self) -> None:
        if not self.host:
            QMessageBox.warning(self, "No address", "Enter the instrument's address.")
            return
        specs = self.registers()
        if not specs:
            QMessageBox.warning(
                self, "No registers", "Add at least one named register to read."
            )
            return
        names = [s.name for s in specs]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            QMessageBox.warning(
                self,
                "Duplicate names",
                "Each register needs its own CSV column: " + ", ".join(duplicates),
            )
            return
        self.accept()
