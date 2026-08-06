"""The main window: pick a device, watch it, record what it says.

The whole application is one loop. A timer drains captured packets, hands the
reassembled chunks to whatever wants them, and repeats. Everything else —
identification, calibration, recording — is a consumer of that one stream, which
is why a session can be recorded while the identification dialog is open and why
calibration does not need its own capture.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
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
    PacketPump,
    capture_readiness,
    describe_interfaces,
    interface_for,
)
from ..capture.neighbors import arp_neighbors
from ..capture.reassembly import C2S, StreamChunk
from ..protocol.framer import (
    TimedStream,
    analyze_flow,
    group_chunks_by_flow,
    split_frames,
)
from ..protocol.profile import DeviceProfile, LiveDecoder, build_profile, load_profiles
from ..protocol.session import Calibration, Observation, SessionDetector
from ..writers.csv_writer import SessionCSVWriter
from ..writers.raw_writer import RawWriter
from .calibrate import CalibrateDialog
from .identify import IdentifyDialog
from .live_view import LiveView

POLL_INTERVAL_MS = 250
REDRAW_INTERVAL_MS = 1000
# Chunks retained for identification while no profile is loaded. Enough for a
# few hundred poll cycles, which is well past what the scan needs.
ANALYSIS_BUFFER = 20000

PROFILE_DIR = Path(__file__).resolve().parents[2] / "profiles"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} {__version__}")
        self.resize(1180, 720)

        self._pump: Optional[PacketPump] = None
        self._profile: Optional[DeviceProfile] = None
        self._decoder: Optional[LiveDecoder] = None
        self._detector: Optional[SessionDetector] = None
        self._csv: Optional[SessionCSVWriter] = None
        self._raw: Optional[RawWriter] = None
        self._analysis_buffer: List[StreamChunk] = []
        self._request_sink: Optional[List[Tuple[float, bytes]]] = None
        self._request_carry = bytearray()
        self._output_dir = Path.home() / "LAN Sniffer Sessions"
        self._session_started: Optional[float] = None

        self._build_ui()
        self._build_menu()
        self._check_readiness()
        self._refresh_profiles()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll)
        self._redraw_timer = QTimer(self)
        self._redraw_timer.timeout.connect(self._live.redraw)

        # Check quietly a moment after startup, so a failed check or a slow
        # network never delays the window appearing.
        QTimer.singleShot(2500, lambda: self._check_updates(silent=True))

    # ----- menu -----------------------------------------------------------

    def _build_menu(self) -> None:
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
            capture_active=self._pump is not None,
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

        device_group = QGroupBox("Device")
        form = QFormLayout(device_group)
        form.addRow("Interface", self._interface)
        form.addRow("Address", device_row)
        form.addRow("Port", self._port)
        form.addRow("Profile", self._profile_box)
        form.addRow(self._capture_btn)

        self._identify_btn = QPushButton("Identify signals…")
        self._identify_btn.clicked.connect(self._identify)
        self._identify_btn.setToolTip(
            "Analyse the traffic captured so far, then name what it finds."
        )
        self._calibrate_btn = QPushButton("Teach idle vs running…")
        self._calibrate_btn.clicked.connect(self._calibrate)

        setup_group = QGroupBox("Set up a device")
        setup = QVBoxLayout(setup_group)
        setup.addWidget(self._identify_btn)
        setup.addWidget(self._calibrate_btn)

        self._session_label = QLabel("No session.")
        self._session_label.setWordWrap(True)
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
        session.addWidget(self._session_label)
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
        for profile in load_profiles(PROFILE_DIR):
            self._profile_box.addItem(profile.name, profile)
        self._profile_box.blockSignals(False)
        if select:
            index = self._profile_box.findText(select)
            if index >= 0:
                self._profile_box.setCurrentIndex(index)
                return
        self._on_profile_changed()

    def _on_profile_changed(self) -> None:
        self._profile = self._profile_box.currentData()
        self._decoder = LiveDecoder(self._profile) if self._profile else None
        self._detector = None
        if self._profile:
            calibration = Calibration.from_dict(self._profile.session or {})
            self._detector = SessionDetector(calibration)
            units = {s.name: s.unit for s in self._profile.signals}
            self._live.set_signals(self._profile.signal_names, units)
            if self._profile.device_port:
                self._port.setValue(self._profile.device_port)
            if self._profile.ip_hint and not self._device.currentText():
                self._device.setEditText(self._profile.ip_hint)
        else:
            self._live.set_signals([], {})
        self._update_controls()

    # ----- capture --------------------------------------------------------

    def _toggle_capture(self) -> None:
        if self._pump is not None:
            self._stop_capture()
            return

        if not self._capture_ready:
            QMessageBox.warning(
                self, "Capture unavailable", self._readiness.text()
            )
            return
        ip = self._selected_ip()
        if not ip:
            QMessageBox.warning(
                self, "No device", "Pick a device address, or type one in."
            )
            return

        port = self._port.value() or None
        self._pump = PacketPump(ip, port, self._resolved_interface())
        try:
            self._pump.start()
        except Exception as e:
            self._pump = None
            QMessageBox.critical(
                self,
                "Could not start capture",
                f"{e}\n\nOn Windows this usually means Npcap is missing or the "
                "app is not running as Administrator. On macOS and Linux it "
                "usually means it was not run with sudo.",
            )
            return

        self._analysis_buffer.clear()
        self._request_carry.clear()
        self._poll_timer.start(POLL_INTERVAL_MS)
        self._redraw_timer.start(REDRAW_INTERVAL_MS)
        self._capture_btn.setText("Stop capture")
        self.statusBar().showMessage(f"Capturing: {self._pump.bpf_filter}")
        self._update_controls()

    def _stop_capture(self) -> None:
        self._poll_timer.stop()
        self._redraw_timer.stop()
        self._close_session(manual=True)
        if self._pump is not None:
            self._pump.stop()
            self._pump = None
        self._capture_btn.setText("Start capture")
        self._update_controls()

    def _poll(self) -> None:
        if self._pump is None:
            return
        chunks = self._pump.poll()
        if chunks:
            self._analysis_buffer.extend(chunks)
            del self._analysis_buffer[:-ANALYSIS_BUFFER]
            self._handle_requests(chunks)
            if self._raw is not None:
                self._raw.add(chunks)
            if self._decoder is not None:
                for sample in self._decoder.feed(chunks):
                    self._live.add(sample.ts, sample.values)
                    if self._csv is not None:
                        self._csv.add(sample.ts, sample.values)

        if self._detector is not None:
            event = self._detector.tick(time.time())
            if event == "stop":
                self._close_session()

        self.statusBar().showMessage(
            f"{self._pump.status()} · {len(self._analysis_buffer)} chunks buffered"
        )
        self._update_session_label()

    def _handle_requests(self, chunks: List[StreamChunk]) -> None:
        """Extract request frames, for calibration and session detection."""
        if self._request_sink is None and self._detector is None:
            return
        for frame_ts, frame in self._iter_requests(chunks):
            if self._request_sink is not None:
                self._request_sink.append((frame_ts, frame))
            if self._detector is not None:
                signature = self._detector.calibration.signature_of(frame)
                if self._detector.observe(Observation(frame_ts, signature)) == "start":
                    self._open_session()

    def _iter_requests(self, chunks: List[StreamChunk]):
        """Split client segments into request frames, carrying partials over."""
        for chunk in chunks:
            if chunk.direction != C2S:
                continue
            if chunk.gap_before:
                self._request_carry.clear()
            self._request_carry.extend(chunk.data)
            if self._profile is None:
                # Without a profile the segment is the best frame guess there is,
                # which is the same fallback the framer uses.
                yield chunk.ts, bytes(self._request_carry)
                self._request_carry.clear()
                continue
            stream = TimedStream()
            stream.append(
                StreamChunk(
                    ts=chunk.ts,
                    flow=chunk.flow,
                    direction=C2S,
                    data=bytes(self._request_carry),
                    stream_offset=0,
                )
            )
            frames = split_frames(stream, self._profile.request_framing)
            consumed = 0
            for frame in frames:
                consumed += len(frame.data)
                yield chunk.ts, frame.data
            del self._request_carry[:consumed]

    # ----- identification and calibration ---------------------------------

    def _identify(self) -> None:
        if not self._analysis_buffer:
            QMessageBox.information(
                self,
                "Nothing captured yet",
                "Start the capture and let the vendor software poll the "
                "instrument for a minute or so, then try again. The scan needs "
                "a few dozen replies before it can tell a measurement from a "
                "header byte.",
            )
            return

        flows = group_chunks_by_flow(self._analysis_buffer)
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

        dialog = IdentifyDialog(analysis, self)
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
        if self._pump is None:
            QMessageBox.information(
                self,
                "Start the capture first",
                "Calibration watches live traffic, so the capture has to be "
                "running before it can compare idle with running.",
            )
            return

        sink: List[Tuple[float, bytes]] = []
        self._request_sink = sink

        def collect() -> List[Tuple[float, bytes]]:
            taken, sink[:] = list(sink), []
            return taken

        dialog = CalibrateDialog(collect, parent=self)
        accepted = dialog.exec_() == CalibrateDialog.Accepted
        self._request_sink = None
        if not accepted or dialog.result is None:
            return

        if self._profile is None:
            QMessageBox.information(
                self,
                "No profile to save it to",
                "The calibration worked, but there is no profile selected to "
                "store it in. Identify the signals first, then calibrate again.",
            )
            return

        self._profile.session = dialog.result.to_dict()
        self._profile.save(PROFILE_DIR / f"{_slug(self._profile.name)}.json")
        self._detector = SessionDetector(dialog.result)
        QMessageBox.information(
            self, "Calibration saved", dialog.result.explanation
        )
        self._update_controls()

    # ----- sessions -------------------------------------------------------

    def _open_session(self, manual: bool = False) -> None:
        if self._csv is not None:
            return
        if self._profile is None:
            QMessageBox.warning(
                self,
                "No profile",
                "Recording needs a profile so the columns have names and units. "
                "Identify the device's signals first.",
            )
            return

        stamp = time.strftime("%Y%m%d_%H%M%S")
        base = self._output_dir / f"{_slug(self._profile.name)}_{stamp}"
        units = {s.name: s.unit for s in self._profile.signals}
        self._csv = SessionCSVWriter(
            base.with_suffix(".csv"), self._profile.signal_names, units
        )
        self._raw = RawWriter(
            Path(str(base) + ".raw.jsonl"),
            device_ip=self._selected_ip(),
            device_port=self._port.value() or None,
            note=f"profile: {self._profile.name}",
        )
        self._session_started = time.time()
        self._live.clear()
        if manual and self._detector is not None:
            self._detector.start(time.time())
        self.statusBar().showMessage(f"Recording to {base.name}.csv", 8000)
        self._update_controls()

    def _close_session(self, manual: bool = False) -> None:
        if self._decoder is not None:
            tail = self._decoder.flush()
            if tail is not None and self._csv is not None:
                self._csv.add(tail.ts, tail.values)
        if self._csv is not None:
            rows = self._csv.rows_written
            self._csv.close()
            self.statusBar().showMessage(f"Session closed — {rows} row(s).", 8000)
        self._csv = None
        if self._raw is not None:
            self._raw.close()
            self._raw = None
        self._session_started = None
        if manual and self._detector is not None:
            self._detector.stop()
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
        if self._csv is not None and self._session_started is not None:
            elapsed = int(time.time() - self._session_started)
            self._session_label.setText(
                f"<b style='color:#1a7f37'>Recording</b> — {elapsed // 60} min "
                f"{elapsed % 60} s, {self._csv.rows_written} row(s)."
            )
        elif self._detector is not None and self._detector.calibration.automatic:
            self._session_label.setText(
                "Waiting — a session will start on its own when an experiment "
                f"begins ({self._detector.calibration.mode} detection)."
            )
        else:
            self._session_label.setText(
                "No session. This device has no automatic detection, so start "
                "and stop recording by hand."
            )

    def _update_controls(self) -> None:
        capturing = self._pump is not None
        recording = self._csv is not None
        self._identify_btn.setEnabled(capturing)
        self._calibrate_btn.setEnabled(capturing)
        self._start_btn.setEnabled(capturing and not recording and self._profile is not None)
        self._stop_btn.setEnabled(recording)
        self._split_btn.setEnabled(recording)
        self._interface.setEnabled(not capturing)
        self._device.setEnabled(not capturing)
        self._port.setEnabled(not capturing)
        self._update_session_label()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._stop_capture()
        super().closeEvent(event)


def _slug(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "_" for c in text.strip()]
    return "".join(keep).strip("_") or "device"
