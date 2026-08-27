"""Work out whether captured traffic can reproduce a vendor software's numbers.

Some instruments never transmit what their software displays. A process mass
spectrometer streams raw detector data and the concentrations are computed in
software, so the published values are absent from the wire however hard one
looks for them.

They may still be *derivable*. This does not try to reverse the instrument's
calibration from first principles; it learns the mapping from data, the same way
the calorimeter's channels were identified — by correlating against a known-good
reference. The difference is that the candidates are positions within an array
rather than byte offsets within a small reply: if the intensity at some band of
array indices tracks the vendor's reading for m/z 18 across a run, that band is
m/z 18.

Correlation is used rather than value matching, and that matters. An array read
with the wrong element type or a stale scale factor still correlates perfectly,
because a linear misreading does not change the shape of a time series — so the
band can be found before the encoding is known. Fits are then reported against a
held-out stretch of the run, never the stretch they were fitted on, because a
scale and offset can be made to match anything over the window used to choose
them.

Nothing here changes how the app records. It answers one question — is there a
mapping at all — and the answer may be no.
"""

from __future__ import annotations

import csv
import math
import warnings
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from ..capture.reassembly import S2C, StreamChunk
from ..protocol.framer import analyze_flow, group_chunks_by_flow

# Replies at least this large are treated as carrying an array rather than a
# handful of scalars.
MIN_ARRAY_BYTES = 512
# Samples needed before a correlation means anything. A vendor logging every
# few seconds gives a few hundred over a half-hour run.
MIN_PAIRED_SAMPLES = 20
# How far into a reply the scalar sweep goes. Generous, because the last search
# of this kind looked at a kilobyte of a 28 KB frame and concluded the values
# were not being sent. Beyond this the array search is the one that applies,
# and `analyse` says so rather than letting the limit pass unmentioned.
MAX_SCALAR_BYTES = 2048
# Below this a capture cannot settle the question either way. Said out loud
# because the last search of this kind ran on eighteen seconds and its empty
# result was read as proof the values are never sent.
MIN_USEFUL_SPAN_S = 300.0
# How far a vendor reading may sit from a frame and still be paired with it.
DEFAULT_TOLERANCE_S = 15.0
# A band grows outwards from its peak while indices stay this good, relative to
# the peak's own correlation.
BAND_RELATIVE_FLOOR = 0.9

# Element types tried when reading an array. Correlation is insensitive to a
# linear misreading, so this list does not have to be exhaustive to find a band.
ELEMENTS: Tuple[Tuple[str, str, int], ...] = (
    ("u32le", "<u4", 4),
    ("u32be", ">u4", 4),
    ("u16le", "<u2", 2),
    ("u16be", ">u2", 2),
    ("i32le", "<i4", 4),
    ("f32le", "<f4", 4),
    ("f32be", ">f4", 4),
)


@dataclass
class ArrayChannel:
    """One request's replies, read as a table of samples against array index."""

    channel: str
    signature: str
    element: str
    byte_offset: int
    values: np.ndarray  # (samples, indices)
    times: List[datetime] = field(default_factory=list)

    @property
    def samples(self) -> int:
        return int(self.values.shape[0])

    @property
    def indices(self) -> int:
        return int(self.values.shape[1])


@dataclass
class BandFit:
    """A stretch of array indices proposed as the source of a vendor reading."""

    vendor_column: str
    channel: str
    element: str
    byte_offset: int
    start: int
    end: int
    scale: float
    bias: float
    subtract_baseline: bool
    r_peak: float
    r_holdout: float
    r2_holdout: float
    samples: int

    @property
    def convincing(self) -> bool:
        """Whether this is strong enough to act on.

        Deliberately judged out of sample. A scale and offset can be made to
        match almost anything over the window they were chosen on.
        """
        return abs(self.r_holdout) >= 0.9 and self.r2_holdout >= 0.8

    def describe(self) -> str:
        where = f"{self.channel} indices {self.start}..{self.end}"
        if self.start == self.end:
            where = f"{self.channel} index {self.start}"
        return (
            f"{self.vendor_column}: {where} as {self.element} "
            f"(offset {self.byte_offset}), "
            f"value = {self.scale:.6g} x aggregate + {self.bias:.6g}"
            + (" minus baseline" if self.subtract_baseline else "")
        )


@dataclass
class ScalarFit:
    """A single field within a reply proposed as the source of a reading."""

    vendor_column: str
    channel: str
    element: str
    byte_offset: int
    scale: float
    bias: float
    r_holdout: float
    r2_holdout: float
    samples: int

    @property
    def convincing(self) -> bool:
        return abs(self.r_holdout) >= 0.9 and self.r2_holdout >= 0.8

    def describe(self) -> str:
        return (
            f"{self.vendor_column}: {self.channel} byte {self.byte_offset} "
            f"as {self.element}, value = {self.scale:.6g} x raw + {self.bias:.6g}"
        )


@dataclass
class Report:
    arrays: List[ArrayChannel] = field(default_factory=list)
    bands: List[BandFit] = field(default_factory=list)
    scalars: List[ScalarFit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def solved(self) -> List[str]:
        names = {f.vendor_column for f in self.bands if f.convincing}
        names |= {f.vendor_column for f in self.scalars if f.convincing}
        return sorted(names)


# ----- reading the capture --------------------------------------------------


def channels_from_chunks(chunks: Sequence[StreamChunk]) -> Dict[str, List[Tuple[float, bytes]]]:
    """Group a capture into request signature -> [(time, reply bytes)].

    Reuses the app's own framing and pairing so that what is analysed here is
    exactly what the recorder would see.
    """
    grouped: Dict[str, List[Tuple[float, bytes]]] = {}
    groups = group_chunks_by_flow(chunks)
    # Channel numbering restarts per flow, so with two instruments in one file
    # their ch0s would land in the same bucket and be correlated as one series.
    devices = {c.device_ip for c in chunks if c.device_ip}
    label = len(devices) > 1
    for (device, _flow), flow_chunks in groups.items():
        analysis = analyze_flow(flow_chunks)
        prefix = f"{device}/" if label and device else ""
        for index, channel in enumerate(analysis.channels):
            key = f"{prefix}ch{index}:{channel.signature_hex}"
            grouped.setdefault(key, [])
            for ts, payload in zip(channel.timestamps, channel.payloads):
                grouped[key].append((ts, payload))
    return grouped


def channels_from_survey(path: Path) -> Dict[str, List[Tuple[float, bytes]]]:
    """Rebuild the same grouping from a survey CSV's hex columns.

    *Record everything* writes three files and the `.raw.jsonl` is the one people
    forget to keep, so accept the CSV as well. It carries the reply bytes and the
    capture clock, which is all this search needs — but only the first
    `MAX_HEX_BYTES` of each reply, marked with a trailing ellipsis. Truncated
    rows are read as far as they go and counted, because a band search over
    quietly shortened arrays would answer the wrong question.
    """
    grouped: Dict[str, List[Tuple[float, bytes]]] = {}
    truncated = 0
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = [c for c in (reader.fieldnames or []) if c.endswith(":hex")]
        for row in reader:
            stamp = (row.get("timestamp_utc") or "").strip()
            if not stamp:
                continue
            try:
                when = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    when = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
            ts = when.replace(tzinfo=timezone.utc).timestamp()
            for column in columns:
                text = (row.get(column) or "").strip()
                if not text:
                    continue
                if text.endswith("..."):
                    text = text[:-3]
                    truncated += 1
                try:
                    payload = bytes.fromhex(text)
                except ValueError:
                    continue
                grouped.setdefault(column[: -len(":hex")] + ":", []).append(
                    (ts, payload)
                )
    if truncated:
        # Not raised: the scalar search still works on a truncated reply, and
        # refusing the file outright would help nobody.
        print(
            f"note: {truncated} replies were cut short in this CSV; "
            "the .raw.jsonl holds them in full",
            file=sys.stderr,
        )
    return grouped


def build_array_channels(
    replies: Dict[str, List[Tuple[float, bytes]]],
    min_bytes: int = MIN_ARRAY_BYTES,
) -> List[ArrayChannel]:
    """Read every large channel as a table of samples against index.

    Each element type and byte alignment is offered separately rather than
    guessed at: picking wrongly would hide the band, and correlation costs
    little enough to try them all.
    """
    out: List[ArrayChannel] = []
    for key, samples in replies.items():
        if len(samples) < MIN_PAIRED_SAMPLES:
            continue
        lengths = {len(p) for _t, p in samples}
        modal = max(lengths, key=lambda n: sum(1 for _t, p in samples if len(p) == n))
        if modal < min_bytes:
            continue
        kept = [(t, p) for t, p in samples if len(p) == modal]
        raw = b"".join(p for _t, p in kept)
        times = [datetime.utcfromtimestamp(t) for t, _p in kept]
        channel, _, signature = key.partition(":")

        for name, dtype, size in ELEMENTS:
            for offset in range(0, size):
                count = (modal - offset) // size
                if count < 16:
                    continue
                # Reading at the wrong alignment produces infinities, which
                # numpy warns about on the way to float64. That is expected
                # here — the whole method is to try every alignment and let
                # correlation reject the nonsense — so the warning is silenced
                # rather than allowed to stop the sweep.
                with np.errstate(invalid="ignore", over="ignore"):
                    block = np.frombuffer(
                        b"".join(p[offset : offset + count * size] for _t, p in kept),
                        dtype=dtype,
                    ).astype(np.float64)
                matrix = block.reshape(len(kept), count)
                if not np.all(np.isfinite(matrix)):
                    continue
                out.append(
                    ArrayChannel(
                        channel=channel,
                        signature=signature,
                        element=name,
                        byte_offset=offset,
                        values=matrix,
                        times=times,
                    )
                )
    return out


# ----- pairing against the vendor export ------------------------------------


def pair_with_vendor(
    times: Sequence[datetime],
    vendor: Sequence[Tuple[datetime, Dict[str, str]]],
    column: str,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> Tuple[np.ndarray, np.ndarray]:
    """Line up one vendor column against frame times. Returns (rows, values).

    Nearest sample within a tolerance, never interpolated: these are readings,
    and a value invented between two of them would be one the instrument never
    reported.
    """
    import bisect

    stamps = [t for t, _v in vendor]
    rows: List[int] = []
    values: List[float] = []
    for i, when in enumerate(times):
        j = bisect.bisect_left(stamps, when)
        best, gap = None, None
        for k in (j - 1, j):
            if 0 <= k < len(stamps):
                d = abs((stamps[k] - when).total_seconds())
                if gap is None or d < gap:
                    best, gap = k, d
        if best is None or gap is None or gap > tolerance_s:
            continue
        text = vendor[best][1].get(column, "")
        try:
            value = float(text)
        except (TypeError, ValueError):
            continue
        rows.append(i)
        values.append(value)
    return np.asarray(rows, dtype=int), np.asarray(values, dtype=float)


# ----- correlation and fitting ----------------------------------------------


def _correlate_columns(matrix: np.ndarray, target: np.ndarray) -> np.ndarray:
    """Pearson r between every column of `matrix` and `target`."""
    with np.errstate(invalid="ignore", divide="ignore", over="ignore"):
        m = matrix - matrix.mean(axis=0, keepdims=True)
        t = target - target.mean()
        denom = np.sqrt((m ** 2).sum(axis=0) * (t ** 2).sum())
        r = (m * t[:, None]).sum(axis=0) / denom
    return np.nan_to_num(r, nan=0.0, posinf=0.0, neginf=0.0)


def _grow_band(r: np.ndarray, peak: int, floor: float) -> Tuple[int, int]:
    """Widen from the peak index while neighbours stay nearly as good."""
    limit = abs(r[peak]) * floor
    start = end = peak
    while start > 0 and abs(r[start - 1]) >= limit:
        start -= 1
    while end < len(r) - 1 and abs(r[end + 1]) >= limit:
        end += 1
    return start, end


def _fit_holdout(x: np.ndarray, y: np.ndarray) -> Tuple[float, float, float, float]:
    """Fit y = a x + b on the first half, score on the second.

    Split by time rather than at random: a run drifts, and a random split lets
    the fit see the same conditions it is later judged on.
    """
    n = len(x)
    cut = max(2, n // 2)
    with np.errstate(invalid="ignore", over="ignore", divide="ignore"), \
            warnings.catch_warnings():
        # A degenerate window is an ordinary outcome of sweeping every offset,
        # and it is caught two lines down. Reporting it as a warning would bury
        # the answer under thousands of lines of it.
        warnings.simplefilter("ignore")
        a, b = np.polyfit(x[:cut], y[:cut], 1)
    if not (np.isfinite(a) and np.isfinite(b)):
        return 0.0, 0.0, 0.0, 0.0
    predicted = a * x[cut:] + b
    actual = y[cut:]
    if len(actual) < 2 or np.std(actual) == 0:
        return float(a), float(b), 0.0, 0.0
    with np.errstate(invalid="ignore", divide="ignore"):
        r = float(np.corrcoef(predicted, actual)[0, 1])
    if not np.isfinite(r):
        return float(a), float(b), 0.0, 0.0
    ss_res = float(((actual - predicted) ** 2).sum())
    ss_tot = float(((actual - actual.mean()) ** 2).sum())
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0
    return float(a), float(b), (0.0 if math.isnan(r) else r), r2


def find_bands(
    arrays: Sequence[ArrayChannel],
    vendor: Sequence[Tuple[datetime, Dict[str, str]]],
    columns: Sequence[str],
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> List[BandFit]:
    """Look for a stretch of array indices that tracks each vendor column."""
    fits: List[BandFit] = []
    for column in columns:
        best: Optional[BandFit] = None
        for array in arrays:
            rows, target = pair_with_vendor(array.times, vendor, column, tolerance_s)
            if len(rows) < MIN_PAIRED_SAMPLES or np.std(target) == 0:
                continue
            matrix = array.values[rows]
            r = _correlate_columns(matrix, target)
            peak = int(np.argmax(np.abs(r)))
            if not np.isfinite(r[peak]) or abs(r[peak]) < 0.5:
                continue
            start, end = _grow_band(r, peak, BAND_RELATIVE_FLOOR)

            for subtract in (False, True):
                block = matrix[:, start : end + 1].mean(axis=1)
                if subtract:
                    block = block - np.median(matrix, axis=1)
                if np.std(block) == 0:
                    continue
                a, b, r_out, r2_out = _fit_holdout(block, target)
                candidate = BandFit(
                    vendor_column=column,
                    channel=array.channel,
                    element=array.element,
                    byte_offset=array.byte_offset,
                    start=start,
                    end=end,
                    scale=a,
                    bias=b,
                    subtract_baseline=subtract,
                    r_peak=float(r[peak]),
                    r_holdout=r_out,
                    r2_holdout=r2_out,
                    samples=len(rows),
                )
                if best is None or abs(candidate.r_holdout) > abs(best.r_holdout):
                    best = candidate
        if best is not None:
            fits.append(best)
    return fits


def find_scalars(
    replies: Dict[str, List[Tuple[float, bytes]]],
    vendor: Sequence[Tuple[datetime, Dict[str, str]]],
    columns: Sequence[str],
    max_bytes: int = MAX_SCALAR_BYTES,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> List[ScalarFit]:
    """Look for a plain field that tracks each vendor column.

    Correlation rather than value matching, which is the point: a reading held
    in counts, or scaled by some factor the vendor software applies later, never
    equals the published number but tracks it exactly.
    """
    fits: List[ScalarFit] = []
    prepared = []
    for key, samples in replies.items():
        if len(samples) < MIN_PAIRED_SAMPLES:
            continue
        lengths = {len(p) for _t, p in samples}
        modal = max(lengths, key=lambda n: sum(1 for _t, p in samples if len(p) == n))
        kept = [(t, p) for t, p in samples if len(p) == modal]
        channel = key.partition(":")[0]
        times = [datetime.utcfromtimestamp(t) for t, _p in kept]
        prepared.append((channel, times, kept, min(modal, max_bytes)))

    for column in columns:
        best: Optional[ScalarFit] = None
        for channel, times, kept, width in prepared:
            rows, target = pair_with_vendor(times, vendor, column, tolerance_s)
            if len(rows) < MIN_PAIRED_SAMPLES or np.std(target) == 0:
                continue
            for name, dtype, size in ELEMENTS:
                for offset in range(0, width - size + 1):
                    with np.errstate(invalid="ignore", over="ignore"):
                        block = np.frombuffer(
                            b"".join(p[offset : offset + size] for _t, p in kept),
                            dtype=dtype,
                        ).astype(np.float64)[rows]
                    if not np.all(np.isfinite(block)) or np.std(block) == 0:
                        continue
                    with np.errstate(invalid="ignore", divide="ignore"):
                        r = float(np.corrcoef(block, target)[0, 1])
                    if not np.isfinite(r) or abs(r) < 0.9:
                        continue
                    a, b, r_out, r2_out = _fit_holdout(block, target)
                    candidate = ScalarFit(
                        vendor_column=column,
                        channel=channel,
                        element=name,
                        byte_offset=offset,
                        scale=a,
                        bias=b,
                        r_holdout=r_out,
                        r2_holdout=r2_out,
                        samples=len(rows),
                    )
                    if best is None or abs(candidate.r_holdout) > abs(best.r_holdout):
                        best = candidate
        if best is not None:
            fits.append(best)
    return fits


def analyse(
    chunks: Sequence[StreamChunk],
    vendor: Sequence[Tuple[datetime, Dict[str, str]]],
    columns: Sequence[str],
    tolerance_s: float = DEFAULT_TOLERANCE_S,
    replies: Optional[Dict[str, List[Tuple[float, bytes]]]] = None,
) -> Report:
    """Run both searches and report what, if anything, reproduces the values.

    `replies` is for the case where the grouping came from somewhere other than a
    raw capture — a survey CSV, say. Passing it skips the framing step.
    """
    report = Report()
    if replies is None:
        replies = channels_from_chunks(chunks)
    if not replies:
        report.notes.append("no request/reply channels found in the capture")
        return report

    stamps = [t for samples in replies.values() for t, _p in samples]
    if stamps:
        span = max(stamps) - min(stamps)
        if span < MIN_USEFUL_SPAN_S:
            report.notes.append(
                f"the capture covers only {span:.0f} s. A channel polled every "
                "few seconds contributes a handful of samples to that, and a "
                "handful of samples correlates with almost anything. Record "
                "the whole run before believing — or disbelieving — this result"
            )

    report.arrays = build_array_channels(replies)
    if not report.arrays:
        report.notes.append(
            f"no channel had {MIN_PAIRED_SAMPLES}+ replies of at least "
            f"{MIN_ARRAY_BYTES} bytes; only the scalar search can apply"
        )

    deep = sorted(
        {
            max(len(p) for _t, p in samples)
            for samples in replies.values()
            if samples and max(len(p) for _t, p in samples) > MAX_SCALAR_BYTES
        }
    )
    if deep:
        report.notes.append(
            f"{len(deep)} channel(s) reply with up to {deep[-1]} bytes; the "
            f"scalar sweep covers the first {MAX_SCALAR_BYTES} of each, and "
            "the rest is searched as arrays"
        )

    report.scalars = find_scalars(replies, vendor, columns, tolerance_s=tolerance_s)
    report.bands = find_bands(report.arrays, vendor, columns, tolerance_s=tolerance_s)

    for column in columns:
        varied = []
        for _ts, row in vendor:
            text = row.get(column, "").strip()
            if text in ("", "nan"):
                continue
            try:
                varied.append(float(text))
            except ValueError:
                # A text column in the export. Not something to correlate, and
                # not a reason to abandon the columns either side of it.
                continue
        if len(varied) > 2:
            lo, hi = min(varied), max(varied)
            if lo != 0 and hi / max(abs(lo), 1e-30) < 1.1:
                report.notes.append(
                    f"{column} varied by less than 10% over the export; "
                    "correlation cannot identify a channel that never moves"
                )
    return report
