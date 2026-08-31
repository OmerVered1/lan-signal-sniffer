"""Point a device at Questor5's results endpoint.

There is no traffic to identify here and no profile to write. Questor names its
own tags and states their units, so the whole configuration is where to ask and
how often — and whether it answers, which is the one thing worth checking
before a run rather than during one.

The test button matters for a specific reason. This endpoint needs Windows
authentication, and the two ways of providing it are not equally available on
every machine: `curl.exe` ships with Windows but only from 1803, and the COM
route needs pywin32. Finding that out here takes a second; finding it out from
an empty column after a thirteen-hour run does not.
"""

from __future__ import annotations

from typing import List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
)

from ..readers.questor import DEFAULT_INTERVAL_S, DEFAULT_PORT, QuestorClient


class QuestorSetupDialog(QDialog):
    """Host, port and poll rate for a Questor5 results reader."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = DEFAULT_PORT,
        interval_s: float = 3.0,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Read from Questor")
        self.setMinimumWidth(560)

        self._host = QLineEdit(host or "localhost")
        self._host.setToolTip(
            "The machine running Questor5. 'localhost' if the sniffer runs on\n"
            "the same PC, otherwise its name or address."
        )
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(int(port or DEFAULT_PORT))

        self._interval = QDoubleSpinBox()
        self._interval.setRange(0.5, 600.0)
        self._interval.setSingleStep(0.5)
        self._interval.setSuffix(" s")
        self._interval.setValue(float(interval_s))
        self._interval.setToolTip(
            "How often to ask. Questor produces a result about every eight\n"
            "seconds, so asking faster gains nothing — several are fetched at\n"
            "a time and repeats are discarded, so a slower rate loses nothing\n"
            "either."
        )

        explain = QLabel(
            "Questor5 computes its results in software and never puts them on "
            "the analyser's link — this reads them from the same endpoint its "
            "own results page uses. It only reads, and changes nothing in "
            "Questor."
        )
        explain.setWordWrap(True)
        explain.setStyleSheet("color:#555;")

        self._test = QPushButton("Test read")
        self._test.clicked.connect(self._run_test)
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setMinimumHeight(150)
        self._output.setStyleSheet("font-family: monospace; font-size: 11px;")
        self._output.setPlainText("Press Test read to see what it answers.")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        form = QFormLayout()
        form.addRow("Host", self._host)
        form.addRow("Port", self._port)
        form.addRow("Ask every", self._interval)

        layout = QVBoxLayout(self)
        layout.addWidget(explain)
        layout.addLayout(form)
        layout.addWidget(self._test)
        layout.addWidget(self._output)
        layout.addWidget(buttons)

    # ----- values ---------------------------------------------------------

    @property
    def host(self) -> str:
        return self._host.text().strip() or "localhost"

    @property
    def port(self) -> int:
        return int(self._port.value())

    @property
    def interval_s(self) -> float:
        return float(self._interval.value())

    # ----- the test -------------------------------------------------------

    def _run_test(self) -> None:
        client = QuestorClient(host=self.host, port=self.port)
        try:
            client.open()
        except Exception as e:
            self._output.setPlainText(
                f"Could not prepare a request:\n\n{e}\n\n"
                "This endpoint needs Windows authentication. On Windows 10 "
                "1803 and later curl.exe provides it; otherwise pywin32 does."
            )
            return

        results = client.poll()
        if client.last_error:
            self._output.setPlainText(
                f"{client.url}\n\nThe request failed:\n\n{client.last_error}"
            )
            return
        if not results:
            self._output.setPlainText(
                f"{client.url}\n\nIt answered, but with no results. That is what "
                "an analyser with nothing recorded yet looks like."
            )
            return

        newest = results[-1]
        lines = [
            f"{client.url}",
            f"reading via {client.transport.name}",
            "",
            f"{len(results)} result set(s); newest at {newest.when:%Y-%m-%d %H:%M:%S}"
            f"  (valve {newest.valve})",
            "",
        ]
        for name in sorted(newest.values):
            unit = newest.units.get(name, "")
            lines.append(f"  {name:<12} {newest.values[name]:>20.9f} {unit}")
        lines += [
            "",
            "Check these against Questor's own Analysis Results page. They "
            "should match to the last digit — if they do not, this is reading "
            "something else.",
        ]
        self._output.setPlainText("\n".join(lines))
