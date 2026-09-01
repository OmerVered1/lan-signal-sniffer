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

# A reading is carried into later rows for this many times its own reporting
# interval. Instruments in one rig report at wildly different rates - an oven
# ten times a second beside an analyser every eight seconds - and without this
# the two never share a row: 72 rows of one recording had both instruments on
# two of them.
#
# It is a multiple of each signal's own cadence rather than a fixed time
# because a fixed one is either too tight for a slow signal or too generous for
# a fast one. Three intervals tolerates a missed reply and no more.
CARRY_INTERVALS = 3.0
# Below this, cadence is too short to be a useful limit on its own.
CARRY_FLOOR_S = 5.0
# Above this nothing is carried, whatever its cadence. A reading a minute old
# is history, not the current state of an instrument.
CARRY_CEILING_S = 120.0


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
    # Whether a signal that did not report on this row keeps the value it last
    # reported. Off, every row holds only what was measured at that instant,
    # which is the truth but leaves two instruments in one file that never
    # share a row.
    carry_forward: bool = True

    _handle: Optional[TextIO] = None
    _writer: Optional[object] = None
    _row: Dict[str, object] = field(default_factory=dict)
    _row_ts: Optional[float] = None
    _t0: Optional[float] = None
    rows_written: int = 0

    _out_of_order: bool = False
    _last_elapsed: float = float("-inf")
    # The most recent reading of each signal, when it was taken, and how often
    # that signal reports - which is what decides how long it may be carried.
    _held: Dict[str, object] = field(default_factory=dict)
    _held_at: Dict[str, float] = field(default_factory=dict)
    _cadence: Dict[str, float] = field(default_factory=dict)
    carried_cells: int = 0

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

    def add(self, ts: float, values: Dict[str, object]) -> None:
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
            # Either direction. A device that answers with a short history
            # delivers older readings after newer ones, and folding one of
            # those into the open row would stamp it with a moment it did not
            # happen at - which is worse than giving it a row of its own.
            expired = abs(ts - self._row_ts) > self.row_timeout
            if repeats or expired:
                self._flush()

        if self._row_ts is None:
            self._row_ts = ts
        self._row.update(values)
        self._remember(ts, values)

        if all(name in self._row for name in self.signal_names):
            self._flush()

    def _remember(self, ts: float, values: Dict[str, object]) -> None:
        """Keep each signal's newest reading, and learn how often it reports."""
        for name, value in values.items():
            previous = self._held_at.get(name)
            if previous is not None and ts > previous:
                gap = ts - previous
                known = self._cadence.get(name)
                # A running average rather than the last gap alone: one late
                # reply should not double the time its signal may be carried.
                self._cadence[name] = gap if known is None else (known * 3 + gap) / 4
            self._held[name] = value
            self._held_at[name] = ts

    def _carry_into(self, row: Dict[str, object], row_ts: float) -> None:
        """Fill a row's gaps with each signal's last reading, while it is current.

        The value written is one the instrument actually reported - never an
        average, never interpolated between two. What makes it honest is the
        limit: a reading is only carried for a few of its own reporting
        intervals, so a signal that has stopped goes blank rather than holding
        its last value across the rest of the run and reading as though the
        instrument were still answering.
        """
        for name in self.signal_names:
            if name in row or name not in self._held:
                continue
            age = row_ts - self._held_at.get(name, row_ts)
            if age < 0:
                # The row predates this reading; carrying it backwards would
                # claim a measurement before it was taken.
                continue
            cadence = self._cadence.get(name, self.row_timeout)
            limit = min(max(cadence * CARRY_INTERVALS, CARRY_FLOOR_S), CARRY_CEILING_S)
            if age <= limit:
                row[name] = self._held[name]
                self.carried_cells += 1

    def close(self) -> None:
        """Write any partial row, put the rows in order, and release the file."""
        self._flush()
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        if self._out_of_order:
            self._sort_by_time()

    def _sort_by_time(self) -> None:
        """Order the rows by when they happened, and re-base the elapsed column.

        Nothing is changed but the order: every row keeps its own timestamp and
        its own values. It has to happen at the end rather than as rows arrive,
        because a reading that belongs earlier can turn up at any point until
        the session stops.

        The elapsed column is re-based on the earliest row rather than the
        first one written, which is what produced negative elapsed times when
        an instrument's first results predated the run.
        """
        import csv as _csv

        try:
            with self.path.open(newline="", encoding="utf-8") as handle:
                rows = list(_csv.reader(handle))
        except OSError:
            return
        if len(rows) < 3:
            return
        header, body = rows[0], rows[1:]

        def when(row):
            try:
                return float(row[1])
            except (IndexError, ValueError):
                return 0.0

        body.sort(key=when)
        base = when(body[0])
        for row in body:
            try:
                row[1] = f"{float(row[1]) - base:.3f}"
            except (IndexError, ValueError):
                continue
        try:
            with self.path.open("w", newline="", encoding="utf-8") as handle:
                writer = _csv.writer(handle)
                writer.writerow(header)
                writer.writerows(body)
        except OSError:
            # The rows are all present and correctly stamped either way; only
            # their order would be lost, which is not worth losing the file for.
            return

    # ----- internals -----------------------------------------------------

    def _flush(self) -> None:
        if not self._row or self._writer is None or self._row_ts is None:
            return
        if self.carry_forward:
            self._carry_into(self._row, self._row_ts)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self._row_ts))
        fractional = self._row_ts - int(self._row_ts)
        elapsed = self._row_ts - (self._t0 if self._t0 is not None else self._row_ts)
        row = [f"{stamp}.{int(fractional * 1000):03d}", f"{elapsed:.3f}"]
        for name in self.signal_names:
            value = self._row.get(name)
            if value is None:
                row.append("")
            elif isinstance(value, str):
                # The survey export carries raw reply bytes as hex alongside the
                # decoded columns, so not every cell is a number.
                row.append(value)
            else:
                row.append(f"{value:.9g}")
        if elapsed < self._last_elapsed:
            # A reading can only be written once it has arrived, and one
            # instrument's results arrive seconds after the moment they
            # describe. That leaves the file out of order, which no analysis
            # expects, so it is sorted when the session closes.
            self._out_of_order = True
        self._last_elapsed = max(self._last_elapsed, elapsed)
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
