"""The main window: pick the devices, watch them, record what they say.

The whole application is one loop. A timer drains captured packets, hands the
reassembled chunks to whatever wants them, and repeats. Everything else —
identification, calibration, recording — is a consumer of that one stream, which
is why a session can be recorded while the identification dialog is open and why
calibration does not need its own capture.

Several devices can be watched at once and share a single session file.
Each has its own capture, decoder and run detector — all held in a
DeviceMonitor — while the file, the plot and the recording state are the
window's, because they are common to the whole setup.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from .._version import __app_name__, __version__
from ..capture.capture import (
    capture_readiness,
    describe_interfaces,
    interface_for,
)
from ..capture.neighbors import arp_neighbors
from ..capture.reassembly import StreamChunk
from ..monitor import DeviceConfig, DeviceMonitor
from ..protocol.framer import analyze_flow, group_chunks_by_flow
from ..protocol.profile import (
    DeviceProfile,
    build_profile,
    load_profiles,
    user_profile_dir,
)
from ..protocol.session import Calibration
from ..writers.csv_writer import SessionCSVWriter
from ..writers.raw_writer import RawWriter
from .calibrate import CalibrateDialog
from .identify import IdentifyDialog
from .live_view import LiveView

POLL_INTERVAL_MS = 250
REDRAW_INTERVAL_MS = 1000

# Profiles are read from both the installation and the user's own folder;
# everything written goes to the latter so it survives an update.
PROFILE_DIR = user_profile_dir()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} {__version__}")
        self.resize(1180, 720)

        # Several devices can be watched at once and share one session file,
        # so everything per-device lives in a monitor rather than on the window.
        self._monitors: List[DeviceMonitor] = [
            DeviceMonitor(DeviceConfig(label="Device 1"))
        ]
        self._current = 0
        self._capturing = False
        self._csv: Optional[SessionCSVWriter] = None
        self._raw: Optional[RawWriter] = None
        self._output_dir = Path.home() / "LAN Sniffer Sessions"
        self._session_started: Optional[float] = None
        self._survey_raw: Optional[RawWriter] = None
        self._survey_base: Optional[Path] = None

        self._build_ui()
        self._build_menu()
        self._check_readiness()
        self._refresh_profiles()
        self._refresh_device_picker()
        self._load_device_form()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll)
        self._redraw_timer = QTimer(self)
        self._redraw_timer.timeout.connect(self._live.redraw)

        # Check quietly a moment after startup, so a failed check or a slow
        # network never delays the window appearing.
        QTimer.singleShot(2500, lambda: self._check_updates(silent=True))

    # ----- menu -----------------------------------------------------------

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        merge = file_menu.addAction("Merge a vendor export into a session\u2026")
        merge.setToolTip(
            "Add an instrument software's own exported columns to a recorded "
            "session, joined on the clock."
        )
        merge.triggered.connect(self._merge_export)

        help_menu = self.menuBar().addMenu("&Help")

        check = help_menu.addAction("Check for updates…")
        check.triggered.connect(lambda: self._check_updates(silent=False))

        help_menu.addSeparator()
        about = help_menu.addAction(f"About {__app_name__}")
        about.triggered.connect(self._show_about)

    def _check_updates(self, silent: bool) -> None:
        from ..updater import check_for_updates

        check_for_updates(
            __version__,
            parent=self,
            silent_if_uptodate=silent,
            capture_active=self._capturing,
        )

    def _show_about(self) -> None:
        state = capture_readiness()
        QMessageBox.about(
            self,
            f"About {__app_name__}",
            f"<b>{__app_name__}</b> v{__version__}<br>"
            "Passive capture and decoding of LAN instrument traffic.<br><br>"
            f"Capture backend: {state.detail}.<br>"
            f"<a href='https://github.com/OmerVered1/lan-signal-sniffer'>"
            "github.com/OmerVered1/lan-signal-sniffer</a>",
        )

    # ----- merging a vendor export ----------------------------------------

    def _merge_export(self) -> None:
        """Join an instrument software's own export onto a recorded session.

        Not every instrument transmits the numbers its software publishes. A
        process mass spectrometer streams raw detector arrays and computes the
        concentrations in software, so sniffing recovers arrays and not values.
        Where the clocks agree the two files can be joined on time instead,
        which reaches the same combined table by another route.
        """
        from ..writers.merge import merge_into_session

        session, _f = QFileDialog.getOpenFileName(
            self, "Which recorded session?", str(self._output_dir), "Session CSV (*.csv)"
        )
        if not session:
            return
        export, _f = QFileDialog.getOpenFileName(
            self,
            "Which vendor export?",
            str(Path(session).parent),
            "Exports (*.csv *.txt *.tsv);;All files (*)",
        )
        if not export:
            return

        from PyQt5.QtWidgets import QInputDialog

        prefix, ok = QInputDialog.getText(
            self,
            "Name these columns",
            "Prefix for the export's columns, so the two instruments stay "
            "apart (blank for none):",
            QLineEdit.Normal,
            "ms.",
        )
        if not ok:
            return

        out = Path(session).with_name(Path(session).stem + "_merged.csv")
        try:
            result = merge_into_session(
                Path(session), Path(export), out, prefix=prefix.strip()
            )
        except Exception as e:
            QMessageBox.critical(self, "Could not merge", str(e))
            return

        message = (
            f"{result.rows} row(s) written, {result.matched} of them carrying a "
            f"reading ({result.coverage:.0%}).\n\n"
            f"Added: {', '.join(result.added_columns)}\n\nSaved as {out.name}"
        )
        if result.warnings:
            message += "\n\n" + "\n".join(result.warnings)
        QMessageBox.information(self, "Merged", message)

    # ----- construction --------------------------------------------------

    def _build_ui(self) -> None:
        self._readiness = QLabel()
        self._readiness.setWordWrap(True)
        self._readiness.setTextFormat(Qt.RichText)

        self._interface = QComboBox()
        self._interface.setToolTip(
            "Which network adapter to listen on. Capture sees only the traffic\n"
            "crossing the adapter you pick, so this has to be the one the\n"
            "instrument is connected through.\n\n"
            "Leave it on automatic: the app matches the instrument's address\n"
            "against each adapter's own address and picks the one on the same\n"
            "link."
        )
        self._populate_interfaces()

        self._device = QComboBox()
        self._device.setEditable(True)
        self._device.setMinimumWidth(220)
        self._device.currentTextChanged.connect(self._on_device_changed)
        self._device.editTextChanged.connect(self._on_device_changed)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_devices)
        device_row = QHBoxLayout()
        device_row.addWidget(self._device, 1)
        device_row.addWidget(refresh)

        self._port = QSpinBox()
        self._port.setRange(0, 65535)
        self._port.setValue(1210)
        self._port.setSpecialValueText("any")
        self._port.setToolTip(
            "Narrows the capture filter. Leave at 'any' if the port is unknown."
        )

        self._profile_box = QComboBox()
        self._profile_box.currentIndexChanged.connect(self._on_profile_changed)

        self._capture_btn = QPushButton("Start capture")
        self._capture_btn.clicked.connect(self._toggle_capture)

        # One form shared by every device, with a selector above it. Duplicating
        # the whole form per device would not fit the panel and would not scale
        # past the two this was asked for.
        self._device_picker = QComboBox()
        self._device_picker.currentIndexChanged.connect(self._on_device_selected)
        self._add_device_btn = QPushButton("Add")
        self._remove_device_btn = QPushButton("Remove")
        for button, tip in (
            (self._add_device_btn, "Watch another instrument at the same time"),
            (self._remove_device_btn, "Stop watching the selected instrument"),
        ):
            button.setToolTip(tip)
        self._add_device_btn.clicked.connect(self._add_device)
        self._remove_device_btn.clicked.connect(self._remove_device)
        picker_row = QHBoxLayout()
        picker_row.addWidget(self._device_picker, 1)
        picker_row.addWidget(self._add_device_btn)
        picker_row.addWidget(self._remove_device_btn)

        self._controls_box = QCheckBox("Its experiment drives recording")
        # Checked by default, and it must be set before anything saves the form:
        # the profile dropdown fires during startup, and an unchecked box would
        # be written back to every device before its own settings were loaded.
        self._controls_box.setChecked(True)
        self._controls_box.setToolTip(
            "Tick this for the instrument that runs the experiment.\n\n"
            "In a coupled setup only one instrument has a run: a TPD rig is an\n"
            "oven under Calisto with a mass spectrometer watching the gas. The\n"
            "oven decides when recording starts and stops; the analyser just\n"
            "contributes its columns for that window."
        )
        self._controls_box.stateChanged.connect(self._on_controls_changed)

        self._label_edit = QLineEdit()
        self._label_edit.setPlaceholderText("a short name, e.g. dsc")
        self._label_edit.setToolTip(
            "Names this device's columns when more than one is being watched,\n"
            "so two instruments reporting 'sample_temperature' stay apart."
        )
        self._label_edit.editingFinished.connect(self._on_label_changed)

        device_group = QGroupBox("Devices")
        form = QFormLayout(device_group)
        form.addRow("Watching", picker_row)
        form.addRow("Name", self._label_edit)
        form.addRow("Interface", self._interface)
        form.addRow("Address", device_row)
        form.addRow("Port", self._port)
        form.addRow("Profile", self._profile_box)
        form.addRow(self._controls_box)
        form.addRow(self._capture_btn)

        self._identify_btn = QPushButton("Identify signals…")
        self._identify_btn.clicked.connect(self._identify)
        self._identify_btn.setToolTip(
            "Analyse the traffic captured so far, then name what it finds."
        )
        self._calibrate_btn = QPushButton("Teach idle vs running…")
        self._calibrate_btn.clicked.connect(self._calibrate)

        self._import_btn = QPushButton("Import profile\u2026")
        self._import_btn.clicked.connect(self._import_profile)
        self._import_btn.setToolTip(
            "Load a profile JSON written elsewhere \u2014 by hand, or by "
            "something\nthat analysed a survey export."
        )

        setup_group = QGroupBox("Set up a device")
        setup = QVBoxLayout(setup_group)
        setup.addWidget(self._identify_btn)
        setup.addWidget(self._calibrate_btn)
        setup.addWidget(self._import_btn)

        self._banner = QLabel("\u25cb  NOT RECORDING")
        self._banner.setAlignment(Qt.AlignCenter)
        self._banner.setStyleSheet(
            "background:#e8e8e8; color:#555; font-weight:bold; font-size:15px; "
            "padding:9px; border-radius:4px;"
        )

        self._session_label = QLabel("No session.")
        self._session_label.setWordWrap(True)
        self._session_label.setTextFormat(Qt.RichText)
        self._session_label.setStyleSheet("color:#555; font-size:11px;")
        self._session_label.setMinimumHeight(46)
        self._start_btn = QPushButton("Start session")
        self._stop_btn = QPushButton("Stop session")
        self._split_btn = QPushButton("Split here")
        self._start_btn.clicked.connect(lambda: self._open_session(manual=True))
        self._stop_btn.clicked.connect(lambda: self._close_session(manual=True))
        self._split_btn.clicked.connect(self._split_session)

        self._output_label = QLabel(str(self._output_dir))
        self._output_label.setWordWrap(True)
        choose_dir = QPushButton("Change folder…")
        choose_dir.clicked.connect(self._choose_output_dir)

        session_group = QGroupBox("Recording")
        session = QVBoxLayout(session_group)
        self._survey_btn = QPushButton("Record everything (no profile)")
        self._survey_btn.setCheckable(True)
        self._survey_btn.clicked.connect(self._toggle_survey)
        self._survey_btn.setToolTip(
            "Record an unidentified device: every reading the scan finds "
            "plausible,\nwith wall-clock timestamps and the raw reply bytes.\n\n"
            "Produces a CSV and a companion JSON for analysis elsewhere \u2014 pair "
            "it\nwith the instrument software's own export of the same run."
        )

        session.addWidget(self._banner)
        session.addWidget(self._session_label)
        session.addWidget(self._survey_btn)
        session.addWidget(self._start_btn)
        session.addWidget(self._stop_btn)
        session.addWidget(self._split_btn)
        session.addWidget(self._output_label)
        session.addWidget(choose_dir)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.addWidget(self._readiness)
        side_layout.addWidget(device_group)
        side_layout.addWidget(setup_group)
        side_layout.addWidget(session_group)
        side_layout.addStretch(1)
        side.setMaximumWidth(430)

        self._live = LiveView()

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(side)
        splitter.addWidget(self._live)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)
        self.setStatusBar(QStatusBar())
        self._update_controls()

    # ----- the device list -------------------------------------------------

    @property
    def _monitor(self) -> DeviceMonitor:
        """The device the form is currently editing."""
        return self._monitors[self._current]

    def _assign_prefixes(self) -> None:
        """Qualify signal names only when more than one device is watched.

        A single-device recording keeps exactly the columns it always had, so
        files from before this existed stay directly comparable.
        """
        multiple = len(self._monitors) > 1
        for monitor in self._monitors:
            monitor.prefix = f"{_slug(monitor.name)}." if multiple else ""

    def _refresh_device_picker(self) -> None:
        self._device_picker.blockSignals(True)
        self._device_picker.clear()
        for i, monitor in enumerate(self._monitors):
            mark = " \u25cf" if monitor.running else ""
            self._device_picker.addItem(f"{monitor.name}{mark}", i)
        self._device_picker.setCurrentIndex(self._current)
        self._device_picker.blockSignals(False)
        self._remove_device_btn.setEnabled(len(self._monitors) > 1)

    def _on_device_selected(self, index: int) -> None:
        if index < 0 or index >= len(self._monitors):
            return
        self._save_device_form()
        self._current = index
        self._load_device_form()

    def _add_device(self) -> None:
        self._save_device_form()
        self._monitors.append(
            DeviceMonitor(DeviceConfig(label=f"Device {len(self._monitors) + 1}"))
        )
        self._current = len(self._monitors) - 1
        self._assign_prefixes()
        self._refresh_device_picker()
        self._load_device_form()
        self._refresh_live_signals()
        if self._capturing:
            self.statusBar().showMessage(
                "Added a device. Restart the capture to include it.", 8000
            )
        self._update_controls()

    def _remove_device(self) -> None:
        if len(self._monitors) < 2:
            return
        monitor = self._monitors.pop(self._current)
        monitor.stop_capture()
        self._current = min(self._current, len(self._monitors) - 1)
        self._assign_prefixes()
        self._refresh_device_picker()
        self._load_device_form()
        self._refresh_live_signals()
        self._update_controls()

    def _load_device_form(self) -> None:
        """Show the selected device's settings in the shared form."""
        config = self._monitor.config
        for widget in (
            self._label_edit,
            self._device,
            self._port,
            self._profile_box,
            self._controls_box,
        ):
            widget.blockSignals(True)
        self._label_edit.setText(config.label)
        self._controls_box.setChecked(config.controls_recording)
        self._device.setEditText(config.ip)
        self._port.setValue(config.port or 0)
        index = (
            self._profile_box.findText(config.profile.name)
            if config.profile
            else 0
        )
        self._profile_box.setCurrentIndex(max(0, index))
        for widget in (
            self._label_edit,
            self._device,
            self._port,
            self._profile_box,
            self._controls_box,
        ):
            widget.blockSignals(False)

        iface = self._interface.findData(config.interface)
        self._interface.setCurrentIndex(iface if iface >= 0 else 0)
        self._on_device_changed()

    def _save_device_form(self) -> None:
        """Write the form back to the selected device."""
        config = self._monitor.config
        config.label = self._label_edit.text().strip() or config.label
        config.ip = self._selected_ip()
        config.port = self._port.value() or None
        config.interface = self._interface.currentData()
        config.controls_recording = self._controls_box.isChecked()

    def _on_controls_changed(self) -> None:
        self._save_device_form()
        self._update_session_label()

    def _on_label_changed(self) -> None:
        self._save_device_form()
        self._assign_prefixes()
        self._refresh_device_picker()
        self._refresh_live_signals()

    def _refresh_live_signals(self) -> None:
        """Rebuild the plot for every signal on every configured device."""
        names: List[str] = []
        units: Dict[str, str] = {}
        for monitor in self._monitors:
            names.extend(monitor.signal_names())
            units.update(monitor.units())
        self._live.set_signals(names, units)

    # ----- readiness and devices -----------------------------------------

    def _check_readiness(self) -> None:
        state = capture_readiness()
        if state.ok:
            text = f"<span style='color:#1a7f37'>Capture ready — {state.detail}.</span>"
            if state.warning:
                text += f"<br><span style='color:#a04000'>{state.warning}</span>"
            self._readiness.setText(text)
        else:
            self._readiness.setText(
                f"<b style='color:#a04000'>Cannot capture: {state.detail}.</b>"
                f"<br>{state.remedy}"
            )
        self._capture_ready = state.ok

    def _populate_interfaces(self) -> None:
        """Fill the adapter list, automatic first."""
        self._interface.clear()
        self._interface.addItem("(automatic)", None)
        for iface in describe_interfaces():
            self._interface.addItem(iface.label(), iface.name)

    def _on_device_changed(self, *_args) -> None:
        """Show which adapter automatic mode has settled on.

        Resolving it silently would leave the user unable to tell a correct
        guess from a wrong one, which matters because the wrong adapter
        captures perfectly and sees nothing.
        """
        if self._interface.currentData() is not None:
            return
        ip = self._selected_ip()
        chosen = interface_for(ip) if ip else None
        label = "(automatic)" if not chosen else f"(automatic — {chosen})"
        self._interface.setItemText(0, label)

    def _resolved_interface(self) -> Optional[str]:
        """The adapter to capture on: the explicit choice, or the best match."""
        explicit = self._interface.currentData()
        if explicit is not None:
            return str(explicit)
        return interface_for(self._selected_ip())

    def _refresh_devices(self) -> None:
        neighbors, diagnostic = arp_neighbors()
        current = self._device.currentText()
        self._device.clear()
        for n in neighbors:
            self._device.addItem(f"{n.ip}  ({n.mac})", n.ip)
        if current:
            self._device.setEditText(current)
        self._populate_interfaces()
        self._on_device_changed()
        self.statusBar().showMessage(
            diagnostic or f"{len(neighbors)} device(s) in the ARP cache", 6000
        )

    def _selected_ip(self) -> str:
        data = self._device.currentData()
        if data:
            return str(data)
        return self._device.currentText().split()[0] if self._device.currentText() else ""

    # ----- profiles -------------------------------------------------------

    def _refresh_profiles(self, select: Optional[str] = None) -> None:
        self._profile_box.blockSignals(True)
        self._profile_box.clear()
        self._profile_box.addItem("(none — identify from traffic)", None)
        for profile in load_profiles():
            self._profile_box.addItem(profile.name, profile)
        self._profile_box.blockSignals(False)
        if select:
            index = self._profile_box.findText(select)
            if index >= 0:
                self._profile_box.setCurrentIndex(index)
                return
        self._on_profile_changed()

    def _on_profile_changed(self) -> None:
        profile = self._profile_box.currentData()
        self._monitor.apply_profile(profile)
        if profile:
            if profile.device_port:
                self._port.setValue(profile.device_port)
            if profile.ip_hint and not self._device.currentText():
                self._device.setEditText(profile.ip_hint)
            if self._monitor.config.label.startswith("Device "):
                # A freshly added device is better named after what it is.
                self._label_edit.setText(profile.name)
        self._save_device_form()
        self._assign_prefixes()
        self._refresh_device_picker()
        self._refresh_live_signals()
        self._update_controls()

    # ----- capture --------------------------------------------------------

    def _toggle_capture(self) -> None:
        if self._capturing:
            self._stop_capture()
            return

        if not self._capture_ready:
            QMessageBox.warning(self, "Capture unavailable", self._readiness.text())
            return

        self._save_device_form()
        unset = [m.name for m in self._monitors if not m.config.ip]
        if unset:
            QMessageBox.warning(
                self,
                "No address",
                "These devices have no address yet: " + ", ".join(unset) + ".",
            )
            return

        started: List[DeviceMonitor] = []
        for monitor in self._monitors:
            interface = monitor.config.interface or interface_for(monitor.config.ip)
            try:
                monitor.start_capture(interface)
            except Exception as e:
                # Leaving the others running would be worse than not starting:
                # a session would silently cover only part of the setup.
                for already in started:
                    already.stop_capture()
                QMessageBox.critical(
                    self,
                    "Could not start capture",
                    f"{monitor.name}: {e}\n\nOn Windows this usually means Npcap "
                    "is missing or the app is not running as Administrator. On "
                    "macOS and Linux it usually means it was not run with sudo.",
                )
                return
            started.append(monitor)

        self._capturing = True
        self._poll_timer.start(POLL_INTERVAL_MS)
        self._redraw_timer.start(REDRAW_INTERVAL_MS)
        self._capture_btn.setText("Stop capture")
        self.statusBar().showMessage(
            "Capturing " + ", ".join(m.name for m in self._monitors)
        )
        self._update_controls()

    def _stop_capture(self) -> None:
        self._poll_timer.stop()
        self._redraw_timer.stop()
        if self._survey_raw is not None:
            self._finish_survey()
        # Not manual=True: shutting the capture down is teardown, not the
        # user ending a session, and must not change the detector's arming.
        self._close_session()
        for monitor in self._monitors:
            monitor.stop_capture()
        self._capturing = False
        self._capture_btn.setText("Start capture")
        self._update_controls()

    def _poll(self) -> None:
        if not self._capturing:
            return

        buffered = 0
        for monitor in self._monitors:
            result = monitor.poll()
            buffered += len(monitor.analysis_buffer)

            if result.chunks:
                if self._raw is not None:
                    self._raw.add(result.chunks)
                if self._survey_raw is not None and monitor is self._monitor:
                    self._survey_raw.add(result.chunks)

            for event, ts in result.events:
                self._on_device_event(monitor, event, ts)

            for sample in result.samples:
                self._live.add(sample.ts, sample.values)
                if self._csv is not None:
                    self._csv.add(sample.ts, sample.values)

            if monitor.tick(time.time()) == "stop":
                self._on_device_event(monitor, "stop", time.time())

        status = " · ".join(
            [f"{m.name}: {m.status()}" for m in self._monitors]
            + [f"{buffered} chunks buffered"]
        )
        if self._survey_raw is not None:
            status += f" · survey: {self._survey_raw.chunks_written} chunks recorded"
        self.statusBar().showMessage(status)
        self._update_session_label()

    def _on_device_event(self, monitor: DeviceMonitor, event: str, ts: float) -> None:
        """Open or close the shared session as devices start and stop.

        Only devices marked as controlling the recording move the file. In a
        coupled setup the experiment belongs to one instrument — a TPD rig's
        run is the oven's, not the mass spectrometer's — and the analyser polls
        continuously with no notion of a run, so it must contribute columns
        without ever opening or closing anything.

        Where several do control it, the file opens on the first to start and
        closes only once all of them have stopped, since closing on the first
        stop would truncate it while another was still going.
        """
        was_running = monitor.running
        monitor.running = event == "start"
        if monitor.running == was_running:
            return
        self._refresh_device_picker()

        if not monitor.config.controls_recording:
            return

        if event == "start":
            if self._csv is None:
                self._open_session()
        elif not any(
            m.running and m.config.controls_recording for m in self._monitors
        ):
            self._close_session()

    # ----- identification and calibration ---------------------------------

    def _identify(self) -> None:
        if not self._monitor.analysis_buffer:
            QMessageBox.information(
                self,
                "Nothing captured yet",
                "Start the capture and let the vendor software poll the "
                "instrument for a minute or so, then try again. The scan needs "
                "a few dozen replies before it can tell a measurement from a "
                "header byte.",
            )
            return

        flows = group_chunks_by_flow(self._monitor.analysis_buffer)
        largest = max(flows.values(), key=len)
        analysis = analyze_flow(largest)
        if not analysis.channels:
            QMessageBox.warning(
                self,
                "No channels found",
                "The traffic was captured but no request/reply pattern emerged. "
                + ("\n".join(analysis.warnings) or "Try capturing for longer."),
            )
            return

        def refresh():
            # Re-analyse the buffer as it grows, so the dialog's values track
            # the instrument while the user is looking at them.
            flows = group_chunks_by_flow(self._monitor.analysis_buffer)
            if not flows:
                return None
            return analyze_flow(max(flows.values(), key=len))

        dialog = IdentifyDialog(analysis, self, refresh=refresh)
        if dialog.exec_() != IdentifyDialog.Accepted:
            return

        name, ok = self._ask_profile_name()
        if not ok:
            return
        profile = build_profile(
            name=name,
            device_port=self._port.value(),
            request_framing=analysis.request_spec,
            chosen=dialog.selections(),
            interaction=analysis.interaction,
            response_framing=analysis.response_spec,
            ip_hint=self._selected_ip(),
        )
        path = PROFILE_DIR / f"{_slug(name)}.json"
        profile.save(path)
        self._refresh_profiles(select=name)
        QMessageBox.information(
            self,
            "Profile saved",
            f"Saved {len(profile.signals)} signal(s) to {path}.\n\n"
            "Next, teach it to spot an experiment so sessions start on their "
            "own — or record by hand with the session buttons.",
        )

    def _ask_profile_name(self) -> Tuple[str, bool]:
        from PyQt5.QtWidgets import QInputDialog

        suggestion = self._selected_ip() or "device"
        return QInputDialog.getText(
            self, "Name this device", "Profile name:", QLineEdit.Normal, suggestion
        )

    def _calibrate(self) -> None:
        if not self._capturing:
            QMessageBox.information(
                self,
                "Start the capture first",
                "Calibration watches live traffic, so the capture has to be "
                "running before it can compare idle with running.",
            )
            return

        sink: List[Tuple[float, bytes]] = []
        self._monitor.request_sink = sink

        def collect() -> List[Tuple[float, bytes]]:
            taken, sink[:] = list(sink), []
            return taken

        dialog = CalibrateDialog(collect, parent=self)
        accepted = dialog.exec_() == CalibrateDialog.Accepted
        self._monitor.request_sink = None
        if not accepted or dialog.result is None:
            return

        if self._monitor.profile is None:
            QMessageBox.information(
                self,
                "No profile to save it to",
                "The calibration worked, but there is no profile selected to "
                "store it in. Identify the signals first, then calibrate again.",
            )
            return

        profile = self._monitor.profile
        profile.session = dialog.result.to_dict()
        profile.save(PROFILE_DIR / f"{_slug(profile.name)}.json")
        self._monitor.apply_profile(profile)
        QMessageBox.information(
            self, "Calibration saved", dialog.result.explanation
        )
        self._update_controls()

    # ----- survey recording -----------------------------------------------

    def _toggle_survey(self) -> None:
        if self._survey_raw is not None:
            self._finish_survey()
        else:
            self._begin_survey()

    def _begin_survey(self) -> None:
        """Record an unidentified device to the raw sidecar.

        Only raw bytes are written while recording. The survey is produced from
        that file at the end rather than accumulated in memory, so an
        experiment that runs for hours costs nothing to hold and survives the
        app being killed — the file can be converted afterwards either way.
        """
        if not self._capturing:
            QMessageBox.information(
                self,
                "Start the capture first",
                "There is nothing to record until the capture is running.",
            )
            self._survey_btn.setChecked(False)
            return

        stamp = time.strftime("%Y%m%d_%H%M%S")
        ip = self._selected_ip() or "device"
        self._survey_base = self._output_dir / f"survey_{_slug(ip)}_{stamp}"
        self._survey_raw = RawWriter(
            Path(str(self._survey_base) + ".raw.jsonl"),
            device_ip=self._selected_ip(),
            device_port=self._port.value() or None,
            note="survey recording (no profile)",
        )
        self._survey_btn.setChecked(True)
        self._survey_btn.setText("Stop and export survey")
        self.statusBar().showMessage(
            f"Recording everything to {self._survey_base.name}.raw.jsonl", 8000
        )
        self._update_controls()

    def _finish_survey(self) -> None:
        from ..writers.raw_writer import read_raw
        from ..writers.survey import build_survey, write_survey

        raw, self._survey_raw = self._survey_raw, None
        base, self._survey_base = self._survey_base, None
        self._survey_btn.setChecked(False)
        self._survey_btn.setText("Record everything (no profile)")
        if raw is None or base is None:
            return

        path = raw.path
        chunks_written = raw.chunks_written
        raw.close()
        self._update_controls()

        if not chunks_written:
            QMessageBox.warning(
                self,
                "Nothing was recorded",
                "No traffic reached the recorder. Check that the right device "
                "and interface are selected and that the instrument software "
                "is actually polling.",
            )
            return

        try:
            survey = build_survey(list(read_raw(path)))
            csv_path, json_path = write_survey(
                survey,
                Path(str(base) + ".csv"),
                device_ip=self._selected_ip(),
                device_port=self._port.value() or None,
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Could not build the survey",
                f"{e}\n\nThe raw capture is intact at:\n{path}\nNothing was lost; "
                "it can be converted again.",
            )
            return

        if not survey.columns:
            QMessageBox.warning(
                self,
                "No readings found",
                "The traffic was recorded but no request/reply pattern emerged, "
                "so there are no columns to export.\n\n"
                + ("\n".join(survey.warnings) or "")
                + f"\n\nThe raw capture is at:\n{path}",
            )
            return

        QMessageBox.information(
            self,
            "Survey exported",
            f"{len(survey.columns)} column(s) over {len(survey.samples)} "
            f"reading(s).\n\n"
            f"Data:      {csv_path.name}\n"
            f"Metadata:  {json_path.name}\n"
            f"Raw bytes: {path.name}\n\n"
            f"In {csv_path.parent}\n\n"
            "Hand the CSV and the JSON to whoever is identifying the signals, "
            "along with the instrument software's own export of the same run — "
            "lining the two up on the clock is what identifies the columns and "
            "shows where the experiment started. The JSON describes the config "
            "format to hand back.",
        )

    # ----- profile import -------------------------------------------------

    def _import_profile(self) -> None:
        """Load a profile written outside the app, refusing a broken one."""
        path, _filter = QFileDialog.getOpenFileName(
            self, "Import a profile", str(self._output_dir), "Profile JSON (*.json)"
        )
        if not path:
            return

        try:
            profile = DeviceProfile.load(Path(path))
        except Exception as e:
            QMessageBox.critical(
                self,
                "Could not read that profile",
                f"{e}\n\nA profile is the JSON described under 'profile_schema' "
                "in a survey export.",
            )
            return

        problems = profile.validate()
        if problems:
            shown = "\n".join(f"  •  {p}" for p in problems[:12])
            if len(problems) > 12:
                shown += f"\n  …and {len(problems) - 12} more."
            QMessageBox.critical(
                self,
                "That profile has problems",
                f"{len(problems)} problem(s) found, so it was not imported:\n\n"
                f"{shown}\n\nMost of these would decode to plausible-looking "
                "numbers rather than failing, so the file is refused rather "
                "than half-applied.",
            )
            return

        destination = PROFILE_DIR / f"{_slug(profile.name)}.json"
        if destination.exists():
            reply = QMessageBox.question(
                self,
                "Replace the existing profile?",
                f"A profile named '{profile.name}' already exists and will be "
                "overwritten.\n\nContinue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        profile.save(destination)
        self._refresh_profiles(select=profile.name)
        QMessageBox.information(
            self,
            "Profile imported",
            f"'{profile.name}' is ready, with {len(profile.signals)} signal(s): "
            + ", ".join(profile.signal_names)
            + ".\n\nStart a session to record with it.",
        )

    # ----- sessions -------------------------------------------------------

    def _open_session(self, manual: bool = False) -> None:
        if self._csv is not None:
            return
        configured = [m for m in self._monitors if m.profile is not None]
        if not configured:
            QMessageBox.warning(
                self,
                "No profile",
                "Recording needs a profile so the columns have names and units. "
                "Identify the device's signals first.",
            )
            return

        stamp = time.strftime("%Y%m%d_%H%M%S")
        stem = (
            _slug(configured[0].profile.name)
            if len(configured) == 1
            else "_".join(_slug(m.name) for m in configured)
        )
        base = _unclaimed(self._output_dir / f"{stem}_{stamp}")
        names: List[str] = []
        units: Dict[str, str] = {}
        for monitor in configured:
            names.extend(monitor.signal_names())
            units.update(monitor.units())
        try:
            self._csv = SessionCSVWriter(
                base.with_suffix(".csv"), names, units
            )
            self._raw = RawWriter(
                Path(str(base) + ".raw.jsonl"),
                # Every device's traffic lands in this one file, including any
                # without a profile — so an instrument that could not be
                # decoded yet is still recorded and can be decoded later.
                device_ip=", ".join(m.config.ip for m in self._monitors if m.config.ip),
                device_port=self._port.value() or None,
                note="; ".join(
                    f"{m.name}: {m.profile.name if m.profile else 'no profile'}"
                    for m in self._monitors
                ),
            )
        except OSError as e:
            # Raised from a timer callback this would vanish into the console
            # and leave the app looking armed but recording nothing.
            self._csv = self._raw = None
            QMessageBox.critical(
                self,
                "Could not start recording",
                f"{e}\n\nThe run is going but nothing is being written. Check "
                f"that this folder exists and is writable:\n{self._output_dir}",
            )
            return
        self._session_started = time.time()
        self._live.mark_session(self._session_started, "start")
        if manual:
            for monitor in self._monitors:
                if monitor.detector is not None:
                    monitor.detector.start(time.time())
                    monitor.running = True
        self.statusBar().showMessage(f"Recording to {base.name}.csv", 8000)
        self._update_controls()

    def _close_session(self, manual: bool = False) -> None:
        for monitor in self._monitors:
            tail = monitor.flush()
            if tail is not None and self._csv is not None:
                self._csv.add(tail.ts, tail.values)
        if self._csv is not None:
            rows = self._csv.rows_written
            self._live.mark_session(time.time(), "stop")
            self._csv.close()
            self.statusBar().showMessage(f"Session closed — {rows} row(s).", 8000)
        self._csv = None
        if self._raw is not None:
            self._raw.close()
            self._raw = None
        self._session_started = None
        if manual:
            for monitor in self._monitors:
                if monitor.detector is not None:
                    monitor.detector.stop()
        for monitor in self._monitors:
            monitor.running = False
        self._refresh_device_picker()
        self._update_controls()

    def _split_session(self) -> None:
        """End the current file and immediately begin the next one."""
        if self._csv is None:
            return
        self._close_session()
        self._open_session()

    def _choose_output_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Where should sessions be saved?", str(self._output_dir)
        )
        if chosen:
            self._output_dir = Path(chosen)
            self._output_label.setText(chosen)

    # ----- state ----------------------------------------------------------

    def _update_session_label(self) -> None:
        """Make the recording state impossible to misread, and say why if not.

        A quiet line of text was not enough: with the plot drawing either way,
        "waiting" and "recording" looked the same at a glance, and a run could
        be missed entirely without anything drawing attention to it.
        """
        if self._csv is not None and self._session_started is not None:
            elapsed = int(time.time() - self._session_started)
            live = sum(1 for m in self._monitors if m.running)
            across = (
                f"   ·   {live}/{len(self._monitors)} devices"
                if len(self._monitors) > 1
                else ""
            )
            self._banner.setText(
                f"⏺  RECORDING   {elapsed // 60:d}:{elapsed % 60:02d}   ·   "
                f"{self._csv.rows_written} rows{across}"
            )
            self._banner.setStyleSheet(
                "background:#1a7f37; color:white; font-weight:bold; "
                "font-size:15px; padding:9px; border-radius:4px;"
            )
            self._session_label.setText(
                f"Writing to <code>{Path(self._csv.path).name}</code>"
            )
            return

        # With several devices the panel reports the one still waiting, since
        # that is the one that would leave a run unrecorded.
        armed = [
            m for m in self._monitors
            if m.detector is not None
            and m.detector.calibration.automatic
            and m.config.controls_recording
        ]
        waiting = [m for m in armed if m.detector.last_trigger_ts is None]
        monitor = (waiting or armed or [None])[0]
        detector = monitor.detector if monitor is not None else None
        automatic = bool(armed)
        self._banner.setText("○  NOT RECORDING" + ("   ·   armed" if automatic else ""))
        self._banner.setStyleSheet(
            "background:#e8e8e8; color:#555; font-weight:bold; font-size:15px; "
            "padding:9px; border-radius:4px;"
        )

        if not automatic:
            self._session_label.setText(
                "This device has no automatic detection, so start and stop "
                "recording by hand."
            )
            return

        # Armed but idle. The two reasons a run can be missed — the capture
        # started after the run did, or the instrument sent a different command
        # — are indistinguishable without this.
        cal = detector.calibration
        trigger = ", ".join(cal.trigger_signatures) or "?"
        if detector.last_trigger_ts is not None:
            ago = int(time.time() - detector.last_trigger_ts)
            state = f"start command last seen {ago} s ago"
        else:
            state = "<b>start command not seen yet</b>"

        who = f"{monitor.name}: " if len(self._monitors) > 1 else ""
        lines = [f"{who}{detector.observed} requests · {state}"]
        if detector.observed > 200 and detector.last_trigger_ts is None:
            lines.append(
                "<span style='color:#a04000'>Run already going? Its start "
                "command came before this capture — press Start session.</span>"
            )
        self._session_label.setText("<br>".join(lines))

        # The full picture goes in the tooltip: useful when a run is missed,
        # noise in the panel the rest of the time.
        detail = [f"Waiting for: {trigger}", f"Stops on: {', '.join(cal.stop_signatures) or 'a quiet period'}"]
        if detector.near_misses:
            detail.append(
                "Similar commands seen from the same family:\n  "
                + "\n  ".join(detector.near_misses)
            )
        self._session_label.setToolTip("\n".join(detail))

    def _update_controls(self) -> None:
        capturing = self._capturing
        recording = self._csv is not None
        self._survey_btn.setEnabled(capturing)
        self._identify_btn.setEnabled(capturing)
        self._calibrate_btn.setEnabled(capturing)
        has_profile = any(m.profile is not None for m in self._monitors)
        self._start_btn.setEnabled(capturing and not recording and has_profile)
        self._stop_btn.setEnabled(recording)
        self._split_btn.setEnabled(recording)
        for widget in (
            self._interface,
            self._device,
            self._port,
            self._label_edit,
            self._add_device_btn,
            self._remove_device_btn,
        ):
            widget.setEnabled(not capturing)
        self._remove_device_btn.setEnabled(
            not capturing and len(self._monitors) > 1
        )
        self._update_session_label()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._stop_capture()
        super().closeEvent(event)


def _unclaimed(base: Path) -> Path:
    """Add a counter if this session name is already taken.

    Session files are named to the second. Two sessions can begin inside the
    same second — Split here, or a run stopped and restarted quickly — and
    without this the second one silently overwrites the first, destroying a
    recording with nothing to indicate it happened.
    """
    candidate = base
    counter = 2
    while candidate.with_suffix(".csv").exists() or Path(
        str(candidate) + ".raw.jsonl"
    ).exists():
        candidate = base.with_name(f"{base.name}_{counter}")
        counter += 1
    return candidate


def _slug(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "_" for c in text.strip()]
    return "".join(keep).strip("_") or "device"
