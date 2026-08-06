"""The idle-versus-running calibration.

Whether the app can tell that an experiment has started is a property of the
vendor software, not something that can be assumed. Some poll only during a run;
some poll continuously from the moment they connect. Rather than bake in a guess,
this dialog records both states and lets the comparison decide — and when nothing
distinguishes them, it says so instead of shipping a detector that fires at
random.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional, Tuple

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from ..protocol.session import Calibration, calibrate_from_requests

# Long enough to see several poll cycles of a slow instrument, short enough that
# nobody skips the step.
DEFAULT_LEG_SECONDS = 120


class CalibrateDialog(QDialog):
    """Records an idle leg and a running leg, then reports what separates them.

    `collector` is called on a timer and returns the (timestamp, request bytes)
    pairs seen since the last call, which keeps this dialog independent of where
    packets come from. Raw bytes rather than reduced signatures, because the
    identifying positions can only be worked out once both legs are in hand.
    """

    def __init__(
        self,
        collector: Callable[[], List[Tuple[float, bytes]]],
        leg_seconds: int = DEFAULT_LEG_SECONDS,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Teach it to spot an experiment")
        self.resize(620, 320)
        self._collector = collector
        self._leg_seconds = leg_seconds
        self._idle: List[Tuple[float, bytes]] = []
        self._running: List[Tuple[float, bytes]] = []
        self._bucket: Optional[List[Tuple[float, bytes]]] = None
        self._deadline = 0.0
        self.result: Optional[Calibration] = None

        self._instructions = QLabel(
            "<p>This finds out whether the vendor software's traffic looks "
            "different while an experiment is running.</p>"
            "<p><b>Step 1.</b> Leave the instrument connected but <b>idle</b> — "
            "no experiment running — and record for "
            f"{leg_seconds // 60} minute(s).</p>"
            "<p><b>Step 2.</b> Start an experiment as you normally would, then "
            "record for the same period.</p>"
        )
        self._instructions.setWordWrap(True)
        self._instructions.setTextFormat(Qt.RichText)

        self._status = QLabel("Ready.")
        self._status.setWordWrap(True)
        self._progress = QProgressBar()
        self._progress.setRange(0, leg_seconds)

        self._idle_btn = QPushButton("Record idle")
        self._run_btn = QPushButton("Record running")
        self._run_btn.setEnabled(False)
        self._idle_btn.clicked.connect(lambda: self._start_leg("idle"))
        self._run_btn.clicked.connect(lambda: self._start_leg("running"))

        row = QHBoxLayout()
        row.addWidget(self._idle_btn)
        row.addWidget(self._run_btn)
        row.addStretch(1)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel, parent=self
        )
        self._buttons.button(QDialogButtonBox.Save).setText("Use this")
        self._buttons.button(QDialogButtonBox.Save).setEnabled(False)
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self._instructions)
        layout.addLayout(row)
        layout.addWidget(self._progress)
        layout.addWidget(self._status, 1)
        layout.addWidget(self._buttons)

        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)

    # ----- recording -----------------------------------------------------

    def _start_leg(self, which: str) -> None:
        self._bucket = self._idle if which == "idle" else self._running
        self._bucket.clear()
        self._deadline = time.monotonic() + self._leg_seconds
        self._idle_btn.setEnabled(False)
        self._run_btn.setEnabled(False)
        self._status.setText(f"Recording the {which} leg…")
        self._timer.start()

    def _tick(self) -> None:
        if self._bucket is None:
            return
        self._bucket.extend(self._collector())
        remaining = max(0.0, self._deadline - time.monotonic())
        self._progress.setValue(int(self._leg_seconds - remaining))
        seen = len(self._bucket)
        self._status.setText(
            f"Recording… {int(remaining)} s left, {seen} request(s) seen."
        )
        if remaining <= 0:
            self._finish_leg()

    def _finish_leg(self) -> None:
        self._timer.stop()
        finished_idle = self._bucket is self._idle
        self._bucket = None
        self._idle_btn.setEnabled(True)

        if finished_idle:
            self._run_btn.setEnabled(True)
            self._status.setText(
                f"Idle leg done — {len(self._idle)} request(s) seen. Now start an "
                "experiment and record the running leg."
            )
            self._idle_btn.setText("Re-record idle")
            return

        self._run_btn.setText("Re-record running")
        self.result = calibrate_from_requests(self._idle, self._running)
        self._buttons.button(QDialogButtonBox.Save).setEnabled(True)
        self._show_result(self.result)

    def _show_result(self, cal: Calibration) -> None:
        if cal.automatic:
            headline = f"<b style='color:#1a7f37'>Automatic detection: {cal.mode}</b>"
        else:
            headline = (
                "<b style='color:#a04000'>Automatic detection is not possible "
                "for this device</b>"
            )
        self._status.setText(
            f"{headline}<br>{cal.explanation}<br><br>"
            f"<span style='color:#555'>Idle {cal.idle_rate:.2f} req/s · "
            f"running {cal.running_rate:.2f} req/s · "
            f"{len(self._idle)} vs {len(self._running)} requests recorded.</span>"
        )
