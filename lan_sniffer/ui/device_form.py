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

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
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
    questor_requested = pyqtSignal(object)
    survey_requested = pyqtSignal(object)

    def __init__(self, monitor: DeviceMonitor, parent=None) -> None:
        super().__init__(parent)
        self.monitor = monitor
        self._menu_actions = []

        # What this device is doing right now, in one line and one colour.
        # Packet counts buried in the status bar answered a question nobody was
        # asking; whether an instrument is alive is the one that matters.
        self._state = QLabel()
        self._state.setTextFormat(Qt.RichText)
        self._state.setContentsMargins(6, 2, 6, 2)

        # The current value of every signal. Without this the only way to see a
        # number was to open the identify dialog, which is a strange place to
        # go to answer "is the oven at temperature yet".
        self._readout = QLabel()
        self._readout.setTextFormat(Qt.RichText)
        self._readout.setWordWrap(True)
        self._readout.setContentsMargins(8, 2, 8, 4)
        self._readout.setStyleSheet(_readout_style(False))
        self._readout.hide()

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
        self._address_row = address_row = QHBoxLayout()
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
        self._questor = QPushButton("Read from Questor…")
        self._survey = QPushButton("Record everything")
        self._remove = QPushButton("Remove device")

        self._identify.setToolTip("Analyse this device's traffic and name what it finds.")
        self._modbus.setToolTip(
            "For an instrument whose software publishes its results in Modbus\n"
            "registers rather than putting them on the wire."
        )
        self._questor.setToolTip(
            "For an Extrel analyser: read the values Questor5 computes, from\n"
            "the endpoint its own results page uses. Nothing is changed in\n"
            "Questor and nothing is asked of the instrument."
        )
        self._survey.setToolTip(
            "Record every plausible reading from this device, with the raw\n"
            "reply bytes, for analysis elsewhere."
        )

        self._identify.clicked.connect(lambda: self.identify_requested.emit(self.monitor))
        self._calibrate.clicked.connect(lambda: self.calibrate_requested.emit(self.monitor))
        self._import.clicked.connect(lambda: self.import_requested.emit(self.monitor))
        self._modbus.clicked.connect(lambda: self.modbus_requested.emit(self.monitor))
        self._questor.clicked.connect(lambda: self.questor_requested.emit(self.monitor))
        self._survey.clicked.connect(lambda: self.survey_requested.emit(self.monitor))
        self._remove.clicked.connect(lambda: self.remove_requested.emit(self.monitor))

        # Most of these are used once per instrument, ever. Left on the card
        # they are seven buttons per device competing with the two that get
        # pressed during a run.
        self._setup = QPushButton("Set up  \u25be")
        menu = QMenu(self._setup)
        for button in (self._calibrate, self._import, self._modbus, self._questor):
            action = menu.addAction(button.text())
            action.setToolTip(button.toolTip())
            action.triggered.connect(button.click)
            self._menu_actions.append((action, button))
        menu.addSeparator()
        remove = menu.addAction(self._remove.text())
        remove.triggered.connect(self._remove.click)
        self._menu_actions.append((remove, self._remove))
        self._setup.setMenu(menu)

        actions = QHBoxLayout()
        actions.setContentsMargins(8, 0, 8, 4)
        for button in (self._identify, self._survey, self._setup):
            actions.addWidget(button)

        self._form = form
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(self._state)
        layout.addLayout(form)
        layout.addLayout(actions)
        layout.addWidget(self._readout)

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

    def show_relevant_fields(self) -> None:
        """Hide the settings this kind of device has no use for.

        A device read from its own software is addressed in its own dialog: an
        adapter, an IP address, a port and a profile are four questions it
        cannot answer, and leaving them on the card made it look misconfigured
        when it was working.
        """
        reader = self.monitor.reads_questor
        for widget in (self._interface, self._port, self._profile):
            self._set_row_visible(widget, not reader)
        # The address sits in a row with its Refresh button, so the form knows
        # it by the layout rather than by the field, and hiding the field alone
        # leaves the word "Address" behind with nothing beside it.
        self._address.setVisible(not reader)
        self._refresh.setVisible(not reader)
        label = self._form.labelForField(self._address_row)
        if label is not None:
            label.setVisible(not reader)
        self._controls.setVisible(not reader)
        self._identify.setVisible(not reader)
        self._survey.setVisible(not reader)

    def _set_row_visible(self, field: QWidget, visible: bool) -> None:
        field.setVisible(visible)
        label = self._form.labelForField(field)
        if label is not None:
            label.setVisible(visible)

    def set_theme(self, dark: bool) -> None:
        self._readout.setStyleSheet(_readout_style(dark))

    def show_state(self, text: str, colour: str, detail: str = "") -> None:
        """The device's own status line, in its own panel."""
        self._state.setText(
            f'<span style="color:{colour}; font-weight:bold;">\u25cf</span> '
            f'<span style="color:{colour};">{text}</span>'
        )
        self._state.setToolTip(detail or text)

    def show_values(self, values, units) -> None:
        """The latest reading of each signal, or nothing if there are none."""
        if not values:
            self._readout.hide()
            return
        cells = []
        for name, value in values.items():
            unit = units.get(name, "")
            short = name.split(".", 1)[-1]
            cells.append(
                f'<td style="padding-right:10px; color:#666;">{short}</td>'
                f'<td style="padding-right:14px; text-align:right;">'
                f'<b>{_readable(value)}</b> <span style="color:#888;">{unit}</span></td>'
            )
        rows = "".join(
            "<tr>" + "".join(cells[i : i + 2]) + "</tr>" for i in range(0, len(cells), 2)
        )
        self._readout.setText(f"<table>{rows}</table>")
        self._readout.show()

    def set_enabled_for_capture(self, capturing: bool, removable: bool) -> None:
        """Lock settings while running; leave the setup actions judged separately."""
        for widget in (self._address, self._port, self._interface, self._label,
                       self._controls, self._profile, self._refresh):
            widget.setEnabled(not capturing)
        self._remove.setEnabled(not capturing and removable)
        self._modbus.setEnabled(not capturing)
        self._questor.setEnabled(not capturing)
        self._import.setEnabled(not capturing)
        sniffing = capturing and not self.monitor.reads_registers
        self._identify.setEnabled(sniffing)
        self._calibrate.setEnabled(sniffing)
        self._survey.setEnabled(sniffing)
        # Last, once every button has been judged: the menu items only mirror
        # the buttons they stand for, and mirroring them early copies a state
        # that is about to change.
        self._setup.setEnabled(True)
        for action, button in self._menu_actions:
            action.setEnabled(button.isEnabled())

    def _emit_changed(self) -> None:
        self.changed.emit(self.monitor)


def _readout_style(dark: bool) -> str:
    from .theme import readout

    return readout(dark)


def _readable(value: float) -> str:
    """A number a person can take in at a glance.

    Signals here span ion currents around 1e-7 and heat flow above 20,000, so
    one fixed format cannot serve both: the small ones would read as zero and
    the large ones would carry meaningless decimals.
    """
    magnitude = abs(value)
    if value == 0:
        return "0"
    if magnitude >= 1000:
        return f"{value:,.0f}"
    if magnitude >= 1:
        return f"{value:.3f}"
    if magnitude >= 0.001:
        return f"{value:.5f}"
    return f"{value:.3e}"
