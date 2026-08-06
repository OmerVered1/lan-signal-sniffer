# READ-ONLY MODULE
"""Find the numeric fields inside a channel's responses, and rank them.

For every byte offset and every plausible encoding, decode the whole time series
and ask how much it looks like a physical measurement. Most readings disqualify
themselves immediately: a misaligned float32 view of a byte stream produces NaNs,
infinities, and values like 1e-38 or 1e+30 within a handful of samples, while a
correctly aligned temperature just drifts.

What survives is ranked, not decided. Two rules break the remaining ties, and
both are priors rather than proofs:

  * Instruments report physical quantities as IEEE floats far more often than as
    scaled integers, so float readings are favoured.
  * A wider field that decodes plausibly is more likely the real one, since a
    narrower reading at the same offset is usually a fragment of it — the high
    two bytes of a float32 read as a u16 will track the float, but it is the
    float that is real.

Because these are priors, every accepted candidate carries the overlapping
readings it outranked in `alternatives`, so the identification UI can offer them
and the user can overrule the ranking. The app ranks; the person decides.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

# Payload lengths beyond this are not swept exhaustively; the scan is O(len).
MAX_SCAN_PAYLOAD = 1024
# Too few samples and every reading looks smooth by accident.
MIN_SAMPLES = 8

# Anything outside this band is not a reading a lab instrument would report.
ABS_MAX = 1e12
# Real measurements are never denormal-small; that is a hallmark of misalignment.
FLOAT_MIN_NONZERO = 1e-20
# Fraction of steps that must share one size before a field is called a counter.
COUNTER_AGREEMENT = 0.90
# Magnitudes a person would recognise as a physical quantity in its own unit.
HUMAN_LO, HUMAN_HI = 1e-3, 1e6

# (name, numpy dtype, byte width, is_float)
ENCODINGS: Tuple[Tuple[str, str, int, bool], ...] = (
    ("f32be", ">f4", 4, True),
    ("f32le", "<f4", 4, True),
    ("f64be", ">f8", 8, True),
    ("f64le", "<f8", 8, True),
    ("i16be", ">i2", 2, False),
    ("i16le", "<i2", 2, False),
    ("u16be", ">u2", 2, False),
    ("u16le", "<u2", 2, False),
    ("i32be", ">i4", 4, False),
    ("i32le", "<i4", 4, False),
    ("u32be", ">u4", 4, False),
    ("u32le", "<u4", 4, False),
)

_ENC_BY_NAME = {name: (dt, size, is_float) for name, dt, size, is_float in ENCODINGS}

_NUMBER_RE = re.compile(rb"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")


@dataclass
class Candidate:
    """One possible numeric field within a channel's response payload."""

    offset: int
    encoding: str
    score: float = 0.0
    is_constant: bool = False
    is_counter: bool = False
    sample_count: int = 0
    minimum: float = 0.0
    maximum: float = 0.0
    latest: float = 0.0
    alternatives: List["Candidate"] = field(default_factory=list)
    preview: List[float] = field(default_factory=list)

    @property
    def width(self) -> int:
        if self.encoding.startswith("ascii"):
            return 0
        return _ENC_BY_NAME[self.encoding][1]

    def describe(self) -> str:
        if self.encoding.startswith("ascii"):
            idx = self.encoding.split("#")[1]
            return f"number #{idx} in the text reply"
        return f"byte {self.offset}, {self.encoding}"

    def to_dict(self) -> dict:
        return {"offset": self.offset, "encoding": self.encoding}

    @classmethod
    def from_dict(cls, d: dict) -> "Candidate":
        return cls(offset=int(d["offset"]), encoding=str(d["encoding"]))


# ----- decoding -------------------------------------------------------------


def _payload_matrix(payloads: Sequence[bytes]) -> Tuple[Optional[np.ndarray], int, int]:
    """Stack equal-length payloads into an (n, width) byte matrix.

    Responses of an off length are dropped rather than padded — a short reply is
    usually a truncated or unrelated message, and padding it would invent bytes.
    """
    if not payloads:
        return None, 0, 0
    lengths: Dict[int, int] = {}
    for p in payloads:
        lengths[len(p)] = lengths.get(len(p), 0) + 1
    modal = max(lengths, key=lambda k: (lengths[k], k))
    kept = [p for p in payloads if len(p) == modal]
    if modal == 0 or len(kept) < MIN_SAMPLES:
        return None, modal, len(payloads) - len(kept)
    mat = np.frombuffer(b"".join(kept), dtype=np.uint8).reshape(len(kept), modal)
    return mat, modal, len(payloads) - len(kept)


def decode_field(
    payloads: Sequence[bytes], offset: int, encoding: str
) -> np.ndarray:
    """Decode one field out of every payload. Short payloads yield NaN."""
    if encoding.startswith("ascii"):
        index = int(encoding.split("#")[1])
        out = np.full(len(payloads), np.nan, dtype=np.float64)
        for i, p in enumerate(payloads):
            found = _NUMBER_RE.findall(p)
            if index < len(found):
                try:
                    out[i] = float(found[index])
                except ValueError:
                    pass
        return out

    dtype, size, _is_float = _ENC_BY_NAME[encoding]
    out = np.full(len(payloads), np.nan, dtype=np.float64)
    for i, p in enumerate(payloads):
        if offset + size <= len(p):
            with np.errstate(over="ignore", invalid="ignore"):
                out[i] = np.frombuffer(p[offset : offset + size], dtype=dtype)[0]
    return out


def _decode_matrix(mat: np.ndarray, offset: int, dtype: str, size: int) -> np.ndarray:
    sub = np.ascontiguousarray(mat[:, offset : offset + size])
    with np.errstate(over="ignore", invalid="ignore"):
        return np.frombuffer(sub.tobytes(), dtype=dtype).astype(np.float64)


# ----- scoring --------------------------------------------------------------


def score_series(values: np.ndarray, is_float: bool, width: int) -> Optional[dict]:
    """Score a decoded time series. Returns None if it is disqualified."""
    if values.size < MIN_SAMPLES:
        return None
    if not np.all(np.isfinite(values)):
        return None

    absv = np.abs(values)
    nonzero = absv[absv > 0]
    if nonzero.size and float(nonzero.max()) > ABS_MAX:
        return None
    if is_float and nonzero.size and float(nonzero.min()) < FLOAT_MIN_NONZERO:
        # Denormal-scale values mean we are reading the tail of some other field.
        return None

    vmin, vmax = float(values.min()), float(values.max())
    is_constant = vmax == vmin

    # A field that advances by the same amount nearly every sample is a
    # transaction id, a sample index, or a clock — never a sensor, which always
    # carries some noise. Left unchecked these score extremely well, because a
    # perfect ramp is the smoothest thing a series can be.
    #
    # "Nearly" rather than "always": a fixed-width counter wraps, and one wrap
    # in a long capture must not disguise it. A quantised sensor is not caught
    # by this, because its steps are dominated by zeros or vary in size.
    diffs = np.diff(values)
    is_counter = False
    if diffs.size >= MIN_SAMPLES - 1:
        steps, counts = np.unique(diffs, return_counts=True)
        order = np.argsort(counts)[::-1]
        for idx in order[:2]:
            if steps[idx] != 0:
                is_counter = counts[idx] / diffs.size >= COUNTER_AGREEMENT
                break

    # Smoothness: how far the signal moves per sample compared with the range it
    # covers. A drifting sensor barely moves; a misaligned reading traverses its
    # whole range every step.
    #
    # Both the typical step and the largest one matter. The average alone is
    # fooled by a field that wraps: the low byte of a register straddling 256
    # counts up quietly and then falls 255 in a single step, which widens its
    # apparent range enough to make the average step look tiny. A real
    # measurement never jumps the width of its own range, so the worst step is
    # the tell.
    if is_constant:
        smooth = 1.0
    else:
        spread = float(np.percentile(values, 95) - np.percentile(values, 5))
        if spread <= 0:
            spread = vmax - vmin
        if spread > 0:
            typical = float(np.mean(np.abs(diffs))) / spread
            worst = float(np.max(np.abs(diffs))) / spread
            smooth = math.exp(-typical / 0.25) * math.exp(-worst / 1.5)
        else:
            smooth = 1.0

    # Magnitude: how much of the series sits at a scale a person would read off
    # an instrument. Reading float bytes as an integer lands around 1e9 and is
    # penalised here.
    if nonzero.size:
        in_band = np.count_nonzero((nonzero >= HUMAN_LO) & (nonzero <= HUMAN_HI))
        magnitude = in_band / nonzero.size
    else:
        magnitude = 0.5  # all zeros — uninformative rather than implausible

    # Resolution: how many distinct values the field actually takes. Smoothness
    # alone is not enough, because a field that barely moves is trivially smooth
    # — a status byte flipping between 1024 and 1025 looks calmer than any real
    # sensor. A measurement channel resolves into many levels; a flag does not.
    distinct = int(np.unique(values).size)
    resolution = min(1.0, distinct / max(1.0, 0.25 * values.size))

    # The width bonus applies to floats only. A narrow reading of a float's
    # bytes really is a fragment of the wider one, so preferring the wider
    # reading is right there. For integers the opposite holds: a wider reading
    # is usually one that has run past the end of the field into its neighbour.
    width_bonus = 0.10 * (math.log2(width) / 3.0) if (is_float and width) else 0.0

    score = (
        0.25 * smooth
        + 0.25 * magnitude
        + 0.20 * resolution
        + (0.20 if is_float else 0.0)
        + width_bonus
    )
    if is_constant:
        # Keep it — a setpoint or serial number may be worth recording — but it
        # should never outrank a channel that actually moves.
        score *= 0.40
    if is_counter:
        score *= 0.35

    return {
        "score": score,
        "is_constant": is_constant,
        "is_counter": is_counter,
        "minimum": vmin,
        "maximum": vmax,
        "latest": float(values[-1]),
    }


def _overlaps(a: Candidate, b: Candidate) -> bool:
    if a.encoding.startswith("ascii") or b.encoding.startswith("ascii"):
        return a.encoding == b.encoding
    return a.offset < b.offset + b.width and b.offset < a.offset + a.width


def _collapse_overlaps(ranked: List[Candidate]) -> List[Candidate]:
    """Keep the best reading of each byte range, filing the rest as alternatives."""
    kept: List[Candidate] = []
    for cand in ranked:
        winner = next((k for k in kept if _overlaps(k, cand)), None)
        if winner is None:
            kept.append(cand)
        else:
            winner.alternatives.append(cand)
    return kept


# ----- entry points ---------------------------------------------------------


@dataclass
class FieldScan:
    """The ranked candidates for one channel, plus what got skipped."""

    candidates: List[Candidate]
    payload_len: int
    samples_used: int
    samples_dropped: int
    warnings: List[str] = field(default_factory=list)


def scan_text_channel(payloads: Sequence[bytes], preview_n: int) -> FieldScan:
    """Pull the numbers out of an ASCII reply by position."""
    counts = [len(_NUMBER_RE.findall(p)) for p in payloads]
    if not counts or max(counts) == 0:
        return FieldScan([], 0, len(payloads), 0, ["no numbers found in the replies"])

    candidates: List[Candidate] = []
    for index in range(max(counts)):
        encoding = f"ascii#{index}"
        values = decode_field(payloads, 0, encoding)
        usable = values[np.isfinite(values)]
        if usable.size < MIN_SAMPLES:
            continue
        stats = score_series(usable, is_float=True, width=8)
        if stats is None:
            continue
        candidates.append(
            Candidate(
                offset=index,
                encoding=encoding,
                sample_count=int(usable.size),
                preview=[float(v) for v in usable[-preview_n:]],
                **stats,
            )
        )
    candidates.sort(key=lambda c: -c.score)
    return FieldScan(candidates, 0, len(payloads), 0)


def scan_channel(
    payloads: Sequence[bytes], preview_n: int = 200
) -> FieldScan:
    """Sweep every offset and encoding, and return ranked candidates."""
    if not payloads:
        return FieldScan([], 0, 0, 0, ["channel has no responses"])

    printable = sum(
        1 for b in payloads[0] if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)
    )
    if payloads[0] and printable / len(payloads[0]) >= 0.9:
        return scan_text_channel(payloads, preview_n)

    mat, payload_len, dropped = _payload_matrix(payloads)
    warnings: List[str] = []
    if dropped:
        warnings.append(
            f"{dropped} reply/replies were not {payload_len} bytes and were skipped"
        )
    if mat is None:
        return FieldScan(
            [],
            payload_len,
            0,
            dropped,
            warnings + [f"need at least {MIN_SAMPLES} same-length replies to analyse"],
        )

    scan_len = payload_len
    if scan_len > MAX_SCAN_PAYLOAD:
        scan_len = MAX_SCAN_PAYLOAD
        warnings.append(
            f"replies are {payload_len} bytes; only the first {MAX_SCAN_PAYLOAD} "
            "were swept"
        )

    found: List[Candidate] = []
    for name, dtype, size, is_float in ENCODINGS:
        for offset in range(0, scan_len - size + 1):
            values = _decode_matrix(mat, offset, dtype, size)
            stats = score_series(values, is_float=is_float, width=size)
            if stats is None:
                continue
            found.append(
                Candidate(
                    offset=offset,
                    encoding=name,
                    sample_count=int(values.size),
                    preview=[float(v) for v in values[-preview_n:]],
                    **stats,
                )
            )

    # Ties break towards the wider reading for floats and the narrower one for
    # integers, for the same reason the width bonus is float-only.
    found.sort(
        key=lambda c: (
            -c.score,
            c.offset,
            -c.width if _ENC_BY_NAME[c.encoding][2] else c.width,
        )
    )
    return FieldScan(
        candidates=_collapse_overlaps(found),
        payload_len=payload_len,
        samples_used=int(mat.shape[0]),
        samples_dropped=dropped,
        warnings=warnings,
    )
