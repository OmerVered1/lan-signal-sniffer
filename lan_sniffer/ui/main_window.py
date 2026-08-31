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

import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QCheckBox,
    QInputDialog,
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
    QScrollArea,
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
from ..protocol.framer import FramingSpec, analyze_flow, group_chunks_by_flow
from ..protocol.profile import (
    SOURCE_MODBUS,
    DeviceProfile,
    build_profile,
    load_profiles,
    user_profile_dir,
)
from ..protocol.session import Calibration
from ..writers.csv_writer import SessionCSVWriter
from ..writers.raw_writer import RawWriter
from .calibrate import CalibrateDialog
from .device_form import DeviceForm
from .modbus_setup import ModbusSetupDialog
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
        self._device_forms: List[DeviceForm] = []
        self._capturing = False
        self._csv: Optional[SessionCSVWriter] = None
        self._raw: Optional[RawWriter] = None
        self._output_dir = Path.home() / "LAN Sniffer Sessions"
        self._session_started: Optional[float] = None
        self._survey_raw: Optional[RawWriter] = None
        self._survey_base: Optional[Path] = None
        self._survey_monitor: Optional[DeviceMonitor] = None

        self._build_ui()
        self._build_menu()
        self._check_readiness()
        for monitor in self._monitors:
            self._add_form(monitor)
        self._update_controls()

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
        from ..writers.merge import (
            export_format,
            merge_into_session,
            session_clock_offset,
        )

        session, _f = QFileDialog.getOpenFileName(
            self, "Which recorded session?", str(self._output_dir), "Session CSV (*.csv)"
        )
        if not session:
            return
        export, _f = QFileDialog.getOpenFileName(
            self,
            "Which vendor export?",
            str(Path(session).parent),
            # All files first, and deliberately: a Questor export arrives with
            # no extension at all, so an extension filter hides the very file
            # this was built to read.
            "All files (*);;Exports (*.csv *.txt *.tsv)",
        )
        if not export:
            return

        from PyQt5.QtWidgets import QInputDialog

        kind = export_format(Path(export))
        reader = {
            "questor": "a Questor5 export (species / ion current)",
            "calisto": "a Calisto export (elapsed times, placed by Zone Start Time)",
            "csv": "a plain CSV with its own timestamp column",
        }[kind]

        # A vendor export stamps in local time and a session in UTC. Guessing
        # wrong here does not fail — it silently matches nothing — so the offset
        # is derived from the session's own name against its own rows, and shown
        # for confirmation rather than assumed.
        derived = session_clock_offset(Path(session))
        offset, ok = QInputDialog.getDouble(
            self,
            "Clock offset",
            f"Reading this as {reader}.\n\n"
            + (
                f"This session was recorded {derived:+g} h from UTC, so that is "
                "how far the export's stamps will be shifted back. Change it "
                "only if the export came from a machine on a different clock."
                if derived is not None
                else "The session's own clock offset could not be worked out "
                "from its name, so this has to be set by hand: how many hours "
                "is the export's clock ahead of UTC?"
            ),
            derived if derived is not None else 0.0,
            -14.0,
            14.0,
            2,
        )
        if not ok:
            return

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
                Path(session),
                Path(export),
                out,
                prefix=prefix.strip(),
                tz_offset_hours=offset,
            )
        except Exception as e:
            QMessageBox.critical(self, "Could not merge", str(e))
            return

        message = (
            f"{result.rows} row(s) written, {result.matched} of them carrying a "
            f"reading ({result.coverage:.0%}).\n\n"
            f"Added: {', '.join(result.added_columns)}\n\nSaved as {out.name}"
        )
        if result.rows and result.coverage < 0.5:
            # Almost always the clock, and worth saying so before the file is
            # taken away and puzzled over.
            message += (
                "\n\nMost rows matched nothing. The usual cause is the clock "
                f"offset — this merge used {offset:+g} h."
            )
        if result.warnings:
            message += "\n\n" + "\n".join(result.warnings)
        QMessageBox.information(self, "Merged", message)

    # ----- construction --------------------------------------------------

    def _build_ui(self) -> None:
        self._readiness = QLabel()
        self._readiness.setWordWrap(True)
        self._readiness.setTextFormat(Qt.RichText)

        # Every device gets its own visible panel. A dropdown that swapped one
        # shared form between them hid the device you were not looking at,
        # which is the wrong shape for setting up a coupled rig.
        self._device_area = QVBoxLayout()
        self._device_area.setContentsMargins(0, 0, 0, 0)
        self._add_device_btn = QPushButton("Add another device")
        self._add_device_btn.clicked.connect(self._add_device)

        self._capture_btn = QPushButton("Start capture")
        self._capture_btn.clicked.connect(self._toggle_capture)

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
        choose_dir = QPushButton("Change folder\u2026")
        choose_dir.clicked.connect(self._choose_output_dir)

        session_group = QGroupBox("Recording")
        session = QVBoxLayout(session_group)
        session.addWidget(self._banner)
        session.addWidget(self._session_label)
        session.addWidget(self._start_btn)
        session.addWidget(self._stop_btn)
        session.addWidget(self._split_btn)
        session.addWidget(self._output_label)
        session.addWidget(choose_dir)

        inner = QWidget()
        side_layout = QVBoxLayout(inner)
        side_layout.addWidget(self._readiness)
        side_layout.addLayout(self._device_area)
        side_layout.addWidget(self._add_device_btn)
        side_layout.addWidget(self._capture_btn)
        side_layout.addWidget(session_group)
        side_layout.addStretch(1)

        # Two device panels plus the recording controls outgrow most windows,
        # so the column scrolls rather than squeezing its contents.
        side = QScrollArea()
        side.setWidget(inner)
        side.setWidgetResizable(True)
        # A minimum as well as a maximum: with only a maximum the splitter
        # collapsed the whole column to a sliver and gave the space to the plot.
        side.setMinimumWidth(430)
        side.setMaximumWidth(520)
        side.setFrameShape(QScrollArea.NoFrame)

        self._live = LiveView()

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(side)
        splitter.addWidget(self._live)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([440, 900])
        splitter.setCollapsible(0, False)
        self.setCentralWidget(splitter)
        self.setStatusBar(QStatusBar())

    # ----- the device panels ------------------------------------------------

    def _add_form(self, monitor: DeviceMonitor) -> DeviceForm:
        form = DeviceForm(monitor)
        form.changed.connect(self._on_form_changed)
        form.remove_requested.connect(self._remove_device)
        form.identify_requested.connect(self._identify)
        form.calibrate_requested.connect(self._calibrate)
        form.import_requested.connect(self._import_profile)
        form.modbus_requested.connect(self._setup_modbus)
        form.questor_requested.connect(self._setup_questor)
        form.survey_requested.connect(self._toggle_survey)
        form.refresh_button.clicked.connect(lambda: self._refresh_devices(monitor))
        self._device_forms.append(form)
        self._device_area.addWidget(form)
        self._populate_form(form)
        form.load()
        return form

    def _populate_form(self, form: DeviceForm) -> None:
        entries = [("(automatic)", None)]
        entries += [(i.label(), i.name) for i in describe_interfaces()]
        form.set_interfaces(entries)
        profiles = [("(none \u2014 identify from traffic)", None)]
        profiles += [(p.name, p) for p in load_profiles()]
        form.set_profiles(profiles)

    def _form_for(self, monitor: DeviceMonitor) -> Optional[DeviceForm]:
        return next((f for f in self._device_forms if f.monitor is monitor), None)

    def _assign_prefixes(self) -> None:
        """Qualify signal names only when more than one device is watched.

        A single-device recording keeps exactly the columns it always had, so
        files from before this existed stay directly comparable.
        """
        multiple = len(self._monitors) > 1
        for monitor in self._monitors:
            monitor.prefix = f"{_slug(monitor.name)}." if multiple else ""

    def _on_form_changed(self, monitor: DeviceMonitor) -> None:
        form = self._form_for(monitor)
        if form is None:
            return
        form.save()
        chosen = form.selected_profile()
        if chosen is not monitor.profile:
            monitor.apply_profile(chosen)
            if chosen:
                if chosen.device_port:
                    form.set_port(chosen.device_port)
                    monitor.config.port = chosen.device_port
                if chosen.ip_hint and not monitor.config.ip:
                    form.set_address(chosen.ip_hint)
                    monitor.config.ip = chosen.ip_hint
                if monitor.config.label.startswith("Device "):
                    form.set_label(chosen.name)
                    monitor.config.label = chosen.name
        self._assign_prefixes()
        self._refresh_live_signals()
        self._update_automatic_labels()
        for other in self._device_forms:
            other.refresh_title()
        self._update_controls()

    def _update_automatic_labels(self) -> None:
        """Show which adapter automatic mode settled on, per device.

        Resolving it silently would leave a wrong guess indistinguishable from
        a right one, and the wrong adapter captures perfectly while seeing
        nothing.
        """
        for form in self._device_forms:
            if form.monitor.reads_registers:
                form.set_automatic_label("(not used when reading registers)")
                continue
            ip = form.selected_ip()
            chosen = interface_for(ip) if ip else None
            form.set_automatic_label(
                f"(automatic \u2014 {chosen})" if chosen else "(automatic)"
            )

    def _add_device(self) -> None:
        monitor = DeviceMonitor(
            DeviceConfig(label=f"Device {len(self._monitors) + 1}")
        )
        self._monitors.append(monitor)
        self._add_form(monitor)
        self._assign_prefixes()
        self._refresh_live_signals()
        for form in self._device_forms:
            form.refresh_title()
        if self._capturing:
            self.statusBar().showMessage(
                "Added a device. Restart the capture to include it.", 8000
            )
        self._update_controls()

    def _remove_device(self, monitor: DeviceMonitor) -> None:
        if len(self._monitors) < 2:
            return
        monitor.stop_capture()
        self._monitors.remove(monitor)
        form = self._form_for(monitor)
        if form is not None:
            self._device_forms.remove(form)
            self._device_area.removeWidget(form)
            form.setParent(None)
            form.deleteLater()
        self._assign_prefixes()
        self._refresh_live_signals()
        for other in self._device_forms:
            other.refresh_title()
        self._update_controls()

    def _refresh_live_signals(self) -> None:
        """Rebuild the plot for every signal on every configured device."""
        names: List[str] = []
        units: Dict[str, str] = {}
        for monitor in self._monitors:
            names.extend(monitor.signal_names())
            units.update(monitor.units())
        self._live.set_signals(names, units)

    def _refresh_profiles(self, select: Optional[str] = None) -> None:
        for form in self._device_forms:
            self._populate_form(form)
        self._refresh_live_signals()
        self._update_controls()

    # ----- readiness and devices -----------------------------------------

    def _check_readiness(self) -> None:
        state = capture_readiness()
        if state.ok:
            text = f"<span style='color:#1a7f37'>Capture ready \u2014 {state.detail}.</span>"
            if state.warning:
                text += f"<br><span style='color:#a04000'>{state.warning}</span>"
            self._readiness.setText(text)
        else:
            self._readiness.setText(
                f"<b style='color:#a04000'>Cannot capture: {state.detail}.</b>"
                f"<br>{state.remedy}"
                "<br><span style='color:#555'>A device read over Modbus does "
                "not need this.</span>"
            )
        self._capture_ready = state.ok

    def _refresh_devices(self, monitor: Optional[DeviceMonitor] = None) -> None:
        neighbors, diagnostic = arp_neighbors()
        entries = [(f"{n.ip}  ({n.mac})", n.ip) for n in neighbors]
        for form in self._device_forms:
            form.set_addresses(entries)
            self._populate_form(form)
        self._update_automatic_labels()
        self.statusBar().showMessage(
            diagnostic or f"{len(neighbors)} device(s) in the ARP cache", 6000
        )

    # ----- capture --------------------------------------------------------

    def _toggle_capture(self) -> None:
        if self._capturing:
            self._stop_capture()
            return

        for form in self._device_forms:
            form.save()

        # Only a device that is watched needs the capture driver. A setup made
        # entirely of instruments read over Modbus should not demand Npcap, or
        # administrator rights, for something it never uses.
        if any(not m.reads_registers for m in self._monitors) and not self._capture_ready:
            QMessageBox.warning(self, "Capture unavailable", self._readiness.text())
            return

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
                    "Could not start",
                    f"{monitor.name}: {e}\n\n"
                    + (
                        "Check that the instrument's Modbus slave is enabled "
                        "and that the address, port and unit id match."
                        if monitor.reads_registers
                        else "On Windows this usually means Npcap is missing "
                        "or the app is not running as Administrator; on macOS "
                        "and Linux, that it was not run with sudo."
                    ),
                )
                return
            started.append(monitor)

        self._capturing = True
        self._poll_timer.start(POLL_INTERVAL_MS)
        self._redraw_timer.start(REDRAW_INTERVAL_MS)
        self.statusBar().showMessage(
            "Running: " + ", ".join(m.name for m in self._monitors)
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
                if self._survey_raw is not None and monitor is self._survey_monitor:
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
        self._refresh_titles()

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

    def _identify(self, monitor: DeviceMonitor) -> None:
        if not monitor.analysis_buffer:
            QMessageBox.information(
                self,
                "Nothing captured yet",
                "Start the capture and let the vendor software poll the "
                "instrument for a minute or so, then try again. The scan needs "
                "a few dozen replies before it can tell a measurement from a "
                "header byte.",
            )
            return

        flows = group_chunks_by_flow(monitor.analysis_buffer)
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
            flows = group_chunks_by_flow(monitor.analysis_buffer)
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
            device_port=monitor.config.port or 0,
            request_framing=analysis.request_spec,
            chosen=dialog.selections(),
            interaction=analysis.interaction,
            response_framing=analysis.response_spec,
            ip_hint=monitor.config.ip,
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

        suggestion = "device"
        return QInputDialog.getText(
            self, "Name this device", "Profile name:", QLineEdit.Normal, suggestion
        )

    def _calibrate(self, monitor: DeviceMonitor) -> None:
        if not self._capturing:
            QMessageBox.information(
                self,
                "Start the capture first",
                "Calibration watches live traffic, so the capture has to be "
                "running before it can compare idle with running.",
            )
            return

        sink: List[Tuple[float, bytes]] = []
        monitor.request_sink = sink

        def collect() -> List[Tuple[float, bytes]]:
            taken, sink[:] = list(sink), []
            return taken

        dialog = CalibrateDialog(collect, parent=self)
        accepted = dialog.exec_() == CalibrateDialog.Accepted
        monitor.request_sink = None
        if not accepted or dialog.result is None:
            return

        if monitor.profile is None:
            QMessageBox.information(
                self,
                "No profile to save it to",
                "The calibration worked, but there is no profile selected to "
                "store it in. Identify the signals first, then calibrate again.",
            )
            return

        profile = monitor.profile
        profile.session = dialog.result.to_dict()
        profile.save(PROFILE_DIR / f"{_slug(profile.name)}.json")
        monitor.apply_profile(profile)
        QMessageBox.information(
            self, "Calibration saved", dialog.result.explanation
        )
        self._update_controls()

    # ----- reading a device over Modbus -----------------------------------

    def _setup_questor(self, monitor: DeviceMonitor) -> None:
        """Point a device at Questor5's results endpoint.

        No profile and no identification: Questor names its own tags and states
        their units, so there is nothing here for the wizard to work out.
        """
        from .questor_setup import QuestorSetupDialog

        dialog = QuestorSetupDialog(
            host=monitor.config.questor_host or "localhost",
            port=monitor.config.questor_port or 80,
            interval_s=monitor.config.questor_interval_s,
            parent=self,
        )
        if dialog.exec_() != QuestorSetupDialog.Accepted:
            return

        if not monitor.config.label or monitor.config.label.startswith("Device "):
            # The name becomes the prefix on fifteen columns, and "device_1" is
            # not what anyone wants to read six months later.
            monitor.config.label = "questor"
        monitor.config.questor_host = dialog.host
        monitor.config.questor_port = dialog.port
        monitor.config.questor_interval_s = dialog.interval_s
        # A reader has no traffic to watch and no run of its own, so it must
        # never be the thing that opens or closes a file: Questor is always
        # acquiring and has no notion of an experiment.
        monitor.config.controls_recording = False
        monitor.apply_profile(None)
        self._refresh_titles()
        self._update_controls()
        QMessageBox.information(
            self,
            "Reading from Questor",
            f"{monitor.name} will read {dialog.host} every "
            f"{dialog.interval_s:g} s.\n\n"
            "Its columns appear once it has answered - Questor names its own "
            "tags, so they are not known until then.",
        )

    def _setup_modbus(self, monitor: DeviceMonitor) -> None:
        """Configure a device whose software publishes values in registers.

        There is no traffic to identify here, so the wizard does not apply.
        What the dialog offers instead is a test read, because a wrong address
        or word order returns numbers rather than an error and the only real
        check is against the instrument's own display.
        """
        profile = monitor.profile
        dialog = ModbusSetupDialog(
            host=monitor.config.ip,
            port=monitor.config.port or 502,
            registers=list(profile.registers) if profile and profile.is_modbus else None,
            settings=dict(profile.modbus) if profile and profile.is_modbus else None,
            parent=self,
        )
        if dialog.exec_() != ModbusSetupDialog.Accepted:
            return

        name, ok = QInputDialog.getText(
            self,
            "Name this device",
            "Profile name:",
            QLineEdit.Normal,
            (profile.name if profile and profile.is_modbus else "") or monitor.name,
        )
        if not ok or not name.strip():
            return

        built = DeviceProfile(
            name=name.strip(),
            device_port=dialog.port,
            request_framing=FramingSpec(mode="single_segment"),
            source=SOURCE_MODBUS,
            modbus=dialog.settings(),
            registers=dialog.registers(),
            ip_hint=dialog.host,
            notes=(
                "Read from the instrument's own Modbus slave rather than "
                "sniffed. The values are the ones its software computed."
            ),
        )
        problems = built.validate()
        if problems:
            QMessageBox.critical(
                self, "That configuration has problems", "\n".join(problems[:10])
            )
            return

        built.save(PROFILE_DIR / f"{_slug(built.name)}.json")
        monitor.config.ip = dialog.host
        monitor.config.port = dialog.port
        monitor.apply_profile(built)
        self._refresh_profiles()
        form = self._form_for(monitor)
        if form is not None:
            self._populate_form(form)
            form.load()
        self._assign_prefixes()
        self._refresh_live_signals()
        self._refresh_titles()
        self._update_controls()
        QMessageBox.information(
            self,
            "Ready to read",
            f"'{built.name}' will read {len(built.registers)} register(s): "
            + ", ".join(built.signal_names)
            + ".\n\nStart the capture to begin.",
        )

    # ----- survey recording -----------------------------------------------

    def _toggle_survey(self, monitor: DeviceMonitor) -> None:
        if self._survey_raw is not None:
            self._finish_survey()
        else:
            self._begin_survey(monitor)

    def _begin_survey(self, monitor: DeviceMonitor) -> None:
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
            return

        stamp = time.strftime("%Y%m%d_%H%M%S")
        self._survey_monitor = monitor
        ip = monitor.config.ip or "device"
        self._survey_base = self._output_dir / f"survey_{_slug(ip)}_{stamp}"
        self._survey_raw = RawWriter(
            Path(str(self._survey_base) + ".raw.jsonl"),
            device_ip=monitor.config.ip,
            device_port=monitor.config.port or None,
            note=f"survey recording: {monitor.name}",
        )
        self.statusBar().showMessage(
            f"Recording everything to {self._survey_base.name}.raw.jsonl", 8000
        )
        self._update_controls()

    def _finish_survey(self) -> None:
        from ..writers.raw_writer import read_raw
        from ..writers.survey import build_survey, write_survey

        raw, self._survey_raw = self._survey_raw, None
        base, self._survey_base = self._survey_base, None
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
                device_ip=self._monitors[0].config.ip,
                device_port=self._monitors[0].config.port or None,
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

    def _import_profile(self, monitor: DeviceMonitor) -> None:
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
        # A session with no profile at all is still worth recording. The raw
        # sidecar holds every byte either way, and that is exactly what an
        # instrument nobody has decoded yet needs — refusing to record it meant
        # the one case the raw file exists for was the one case it was denied.
        # The CSV then has no signal columns, and the banner says so.
        stamp = time.strftime("%Y%m%d_%H%M%S")
        if len(configured) == 1:
            stem = _slug(configured[0].profile.name)
        elif configured:
            stem = "_".join(_slug(m.name) for m in configured)
        else:
            stem = "_".join(_slug(m.name) for m in self._monitors) or "capture"
        base = _unclaimed(self._output_dir / f"{stem}_{stamp}")
        names: List[str] = []
        units: Dict[str, str] = {}
        # Every device that has signals, not only the ones with a profile. A
        # device read from its software's own interface names its columns from
        # what that software answered, and has no profile at all - collecting
        # only from profiled devices left its readings out of the file while
        # recording them perfectly well into memory.
        for monitor in self._monitors:
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
                device_port=self._monitors[0].config.port or None,
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
        if names:
            self.statusBar().showMessage(f"Recording to {base.name}.csv", 8000)
        else:
            self.statusBar().showMessage(
                f"Recording raw traffic to {base.name}.raw.jsonl — no signals "
                "are named, so the CSV will have no data columns.",
                12000,
            )
        self._update_controls()

    def _close_session(self, manual: bool = False) -> None:
        for monitor in self._monitors:
            for tail in monitor.flush():
                if self._csv is not None:
                    self._csv.add(tail.ts, tail.values)
        if self._csv is not None:
            rows = self._csv.rows_written
            named = bool(self._csv.signal_names)
            chunks = self._raw.chunks_written if self._raw is not None else 0
            self._live.mark_session(time.time(), "stop")
            self._csv.close()
            closed = (
                f"Session closed — {rows} row(s)."
                if named
                else f"Session closed — {chunks} chunk(s) of raw traffic."
            )
            self.statusBar().showMessage(closed, 8000)
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
        self._refresh_titles()
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
            if self._csv.signal_names:
                what = f"{self._csv.rows_written} rows"
            else:
                # No profile anywhere, so there is nothing to put in a column.
                # Reporting "0 rows" would read as a recording going wrong.
                chunks = self._raw.chunks_written if self._raw is not None else 0
                what = f"{chunks} chunks · raw only"
            self._banner.setText(
                f"⏺  RECORDING   {elapsed // 60:d}:{elapsed % 60:02d}   ·   "
                f"{what}{across}"
            )
            self._banner.setStyleSheet(
                "background:#1a7f37; color:white; font-weight:bold; "
                "font-size:15px; padding:9px; border-radius:4px;"
            )
            target = Path(self._csv.path).name
            if not self._csv.signal_names:
                target = target[:-4] + ".raw.jsonl" if target.endswith(".csv") else target
            self._session_label.setText(f"Writing to <code>{target}</code>")
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

    def _refresh_titles(self) -> None:
        for form in self._device_forms:
            form.refresh_title()

    def _update_controls(self) -> None:
        capturing = self._capturing
        recording = self._csv is not None
        removable = len(self._monitors) > 1
        for form in self._device_forms:
            form.set_enabled_for_capture(capturing, removable)
        self._add_device_btn.setEnabled(not capturing)

        self._start_btn.setEnabled(capturing and not recording)
        self._stop_btn.setEnabled(recording)
        self._split_btn.setEnabled(recording)
        self._capture_btn.setText("Stop capture" if capturing else "Start capture")
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
    """A column prefix or filename stem, from whatever the device is called.

    Runs of separators collapse: "Setaram Oven (Calisto)" has a space before a
    bracket and becomes setaram_oven_calisto rather than a name with a double
    underscore in the middle of it, which every column then carries.
    """
    keep = [c.lower() if c.isalnum() else "_" for c in text.strip()]
    return re.sub(r"_+", "_", "".join(keep)).strip("_") or "device"
