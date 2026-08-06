"""Write a recorded session to CSV.

Each poll asks the device for one channel, so decoded samples arrive one signal
at a time, a fraction of a second apart. Writing them as they come would give a
file that is mostly blanks. Instead a row is held open until every signal has
reported or the row's time budget runs out, which produces the wide,
one-row-per-cycle table the analysis pipeline expects.

Both an absolute timestamp and an elapsed one are written. The absolute column
is the point of sniffing rather than polling: samples carry the capture clock,
so a C80 file and a Keithley file can be aligned directly instead of having the
offset re-derived from step events in every data set.
"""

from __future__ import annotations

import csv
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, TextIO

# How long a row waits for its remaining signals before being written anyway.
# Comfortably longer than one poll cycle, short enough that a channel dropping
# out does not stall the file.
DEFAULT_ROW_TIMEOUT = 5.0


@dataclass
class SessionCSVWriter:
    """Accumulates decoded samples into rows and writes them out.

    Call `add` for every sample and `close` when the session ends. Rows are
    flushed as soon as they are complete, so the file is readable while the
    experiment is still running.
    """

    path: Path
    signal_names: Sequence[str]
    units: Dict[str, str] = field(default_factory=dict)
    row_timeout: float = DEFAULT_ROW_TIMEOUT

    _handle: Optional[TextIO] = None
    _writer: Optional[object] = None
    _row: Dict[str, float] = field(default_factory=dict)
    _row_ts: Optional[float] = None
    _t0: Optional[float] = None
    rows_written: int = 0

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._handle)
        header = ["timestamp_utc", "elapsed_s"] + [
            f"{name} ({self.units[name]})" if self.units.get(name) else name
            for name in self.signal_names
        ]
        self._writer.writerow(header)

    # ----- input ---------------------------------------------------------

    def add(self, ts: float, values: Dict[str, float]) -> None:
        """Fold one decoded sample into the open row."""
        if self._t0 is None:
            self._t0 = ts

        # Decide the open row's fate before merging anything into it. A sample
        # that repeats a signal already present belongs to the next cycle, and
        # one that arrives past the row's budget means a channel has dropped
        # out — in both cases the row is finished, and folding the new value in
        # first would backdate it into the wrong row.
        if self._row and self._row_ts is not None:
            repeats = any(name in self._row for name in values)
            expired = ts - self._row_ts > self.row_timeout
            if repeats or expired:
                self._flush()

        if self._row_ts is None:
            self._row_ts = ts
        self._row.update(values)

        if all(name in self._row for name in self.signal_names):
            self._flush()

    def close(self) -> None:
        """Write any partial row and release the file."""
        self._flush()
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    # ----- internals -----------------------------------------------------

    def _flush(self) -> None:
        if not self._row or self._writer is None or self._row_ts is None:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self._row_ts))
        fractional = self._row_ts - int(self._row_ts)
        elapsed = self._row_ts - (self._t0 if self._t0 is not None else self._row_ts)
        row = [f"{stamp}.{int(fractional * 1000):03d}", f"{elapsed:.3f}"]
        for name in self.signal_names:
            value = self._row.get(name)
            row.append("" if value is None else f"{value:.9g}")
        self._writer.writerow(row)
        if self._handle is not None:
            self._handle.flush()
        self.rows_written += 1
        self._row = {}
        self._row_ts = None

    def __enter__(self) -> "SessionCSVWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
