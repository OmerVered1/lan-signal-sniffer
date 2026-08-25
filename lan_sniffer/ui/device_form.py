"""One device's settings, shown as its own panel.

A dropdown that swapped one shared form between devices meant only one could be
seen at a time, which is the wrong shape for a coupled rig: setting up an oven
and a gas analyser side by side means comparing them, not remembering the one
that is hidden.

Each device therefore gets its own panel, and the actions that operate on a
device — identify, calibrate, import, set up registers — live inside it. That
removes the question of which device a button applies to, which a shared row of
buttons could only answer by implication.
"""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..monitor import DeviceMonitor


class DeviceForm(QGroupBox):
    """The settings and actions for a single device."""

    changed = pyqtSignal(object)
    remove_requested = pyqtSignal(object)
    identify_requested = pyqtSignal(object)
    calibrate_requested = pyqtSignal(object)
    import_requested = pyqtSignal(object)
    modbus_requested = pyqtSignal(object)
    survey_requested = pyqtSignal(object)

    def __init__(self, monitor: DeviceMonitor, parent=None) -> None:
        super().__init__(parent)
        self.monitor = monitor

        self._label = QLineEdit()
        self._label.setPlaceholderText("a short name, e.g. oven")
        self._label.setToolTip(
            "Names this device's columns when more than one is watched, so two\n"
            "instruments reporting 'sample_temperature' stay apart."
        )
        self._label.editingFinished.connect(self._emit_changed)

        self._interface = QComboBox()
        self._interface.setToolTip(
            "Which network adapter to listen on. Capture sees only traffic\n"
            "crossing the adapter you pick.\n\n"
            "Leave it automatic: the address is matched against each adapter's\n"
            "own address to find the one on the same link."
        )

        self._address = QComboBox()
        self._address.setEditable(True)
        self._address.setMinimumWidth(170)
        self._address.editTextChanged.connect(lambda _t: self._emit_changed())
        self._refresh = QPushButton("Refresh")
        address_row = QHBoxLayout()
        address_row.addWidget(self._address, 1)
        address_row.addWidget(self._refresh)

        self._port = QSpinBox()
        self._port.setRange(0, 65535)
        self._port.setSpecialValueText("any")
        self._port.valueChanged.connect(lambda _v: self._emit_changed())

        self._profile = QComboBox()
        self._profile.currentIndexChanged.connect(lambda _i: self._emit_changed())

        self._controls = QCheckBox("Its experiment drives recording")
        self._controls.setChecked(True)
        self._controls.setToolTip(
            "Tick this for the instrument that runs the experiment.\n\n"
            "In a coupled setup only one has a run: a TPD rig is an oven under\n"
            "Calisto with a mass spectrometer watching the gas. The oven decides\n"
            "when recording starts and stops; the analyser contributes columns."
        )
        self._controls.stateChanged.connect(lambda _s: self._emit_changed())

        form = QFormLayout()
        form.setContentsMargins(8, 4, 8, 4)
        form.addRow("Name", self._label)
        form.addRow("Interface", self._interface)
        form.addRow("Address", address_row)
        form.addRow("Port", self._port)
        form.addRow("Profile", self._profile)
        form.addRow(self._controls)

        self._identify = QPushButton("Identify signals…")
        self._calibrate = QPushButton("Teach idle vs running…")
        self._import = QPushButton("Import profile…")
        self._modbus = QPushButton("Read over Modbus…")
        self._survey = QPushButton("Record everything")
        self._remove = QPushButton("Remove device")

        self._identify.setToolTip("Analyse this device's traffic and name what it finds.")
        self._modbus.setToolTip(
            "For an instrument whose software publishes its results in Modbus\n"
            "registers rather than putting them on the wire."
        )
        self._survey.setToolTip(
            "Record every plausible reading from this device, with the raw\n"
            "reply bytes, for analysis elsewhere."
        )

        self._identify.clicked.connect(lambda: self.identify_requested.emit(self.monitor))
        self._calibrate.clicked.connect(lambda: self.calibrate_requested.emit(self.monitor))
        self._import.clicked.connect(lambda: self.import_requested.emit(self.monitor))
        self._modbus.clicked.connect(lambda: self.modbus_requested.emit(self.monitor))
        self._survey.clicked.connect(lambda: self.survey_requested.emit(self.monitor))
        self._remove.clicked.connect(lambda: self.remove_requested.emit(self.monitor))

        actions = QGridLayout()
        actions.setContentsMargins(8, 0, 8, 4)
        for i, button in enumerate(
            (self._identify, self._calibrate, self._import, self._modbus,
             self._survey, self._remove)
        ):
            actions.addWidget(button, i // 2, i % 2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addLayout(form)
        layout.addLayout(actions)

    # ----- wiring ---------------------------------------------------------

    @property
    def refresh_button(self) -> QPushButton:
        return self._refresh

    def set_interfaces(self, entries) -> None:
        """entries: [(label, data)] with the automatic choice first."""
        current = self._interface.currentData()
        self._interface.blockSignals(True)
        self._interface.clear()
        for label, data in entries:
            self._interface.addItem(label, data)
        index = self._interface.findData(current)
        self._interface.setCurrentIndex(index if index >= 0 else 0)
        self._interface.blockSignals(False)

    def set_automatic_label(self, text: str) -> None:
        if self._interface.count():
            self._interface.setItemText(0, text)

    def set_addresses(self, entries) -> None:
        typed = self._address.currentText()
        self._address.blockSignals(True)
        self._address.clear()
        for label, data in entries:
            self._address.addItem(label, data)
        self._address.setEditText(typed)
        self._address.blockSignals(False)

    def set_profiles(self, profiles) -> None:
        """profiles: [(name, DeviceProfile or None)]."""
        current = self.monitor.profile.name if self.monitor.profile else None
        self._profile.blockSignals(True)
        self._profile.clear()
        for name, profile in profiles:
            self._profile.addItem(name, profile)
        if current:
            index = self._profile.findText(current)
            if index >= 0:
                self._profile.setCurrentIndex(index)
        self._profile.blockSignals(False)

    # ----- the config -----------------------------------------------------

    def load(self) -> None:
        """Show the monitor's settings."""
        config = self.monitor.config
        for widget in (self._label, self._address, self._port, self._controls):
            widget.blockSignals(True)
        self._label.setText(config.label)
        self._address.setEditText(config.ip)
        self._port.setValue(config.port or 0)
        self._controls.setChecked(config.controls_recording)
        for widget in (self._label, self._address, self._port, self._controls):
            widget.blockSignals(False)
        index = self._interface.findData(config.interface)
        self._interface.setCurrentIndex(index if index >= 0 else 0)
        self.refresh_title()

    def save(self) -> None:
        """Write what is shown back to the monitor."""
        config = self.monitor.config
        config.label = self._label.text().strip() or config.label
        config.ip = self.selected_ip()
        config.port = self._port.value() or None
        config.interface = self._interface.currentData()
        config.controls_recording = self._controls.isChecked()

    def selected_ip(self) -> str:
        data = self._address.currentData()
        if data:
            return str(data)
        text = self._address.currentText()
        return text.split()[0] if text else ""

    def selected_profile(self):
        return self._profile.currentData()

    def select_profile(self, name: str) -> bool:
        """Choose a profile by name. Returns whether it was found."""
        index = self._profile.findText(name)
        if index < 0:
            return False
        self._profile.setCurrentIndex(index)
        return True

    def set_port(self, port: int) -> None:
        self._port.blockSignals(True)
        self._port.setValue(port)
        self._port.blockSignals(False)

    def set_address(self, ip: str) -> None:
        self._address.blockSignals(True)
        self._address.setEditText(ip)
        self._address.blockSignals(False)

    def set_label(self, text: str) -> None:
        self._label.setText(text)

    # ----- appearance -----------------------------------------------------

    def refresh_title(self) -> None:
        mark = "  ●" if self.monitor.running else ""
        kind = " · Modbus" if self.monitor.reads_registers else ""
        self.setTitle(f"{self.monitor.name}{kind}{mark}")

    def set_enabled_for_capture(self, capturing: bool, removable: bool) -> None:
        """Lock settings while running; leave the setup actions judged separately."""
        for widget in (self._address, self._port, self._interface, self._label,
                       self._controls, self._profile, self._refresh):
            widget.setEnabled(not capturing)
        self._remove.setEnabled(not capturing and removable)
        self._modbus.setEnabled(not capturing)
        self._import.setEnabled(not capturing)
        sniffing = capturing and not self.monitor.reads_registers
        self._identify.setEnabled(sniffing)
        self._calibrate.setEnabled(sniffing)
        self._survey.setEnabled(sniffing)

    def _emit_changed(self) -> None:
        self.changed.emit(self.monitor)
