# READ-ONLY MODULE
"""Infer where protocol frames begin and end, with no device-specific knowledge.

Pure byte-stream analysis is ambiguous: a stream of 6-byte frames parses just as
cleanly into 3-byte or 2-byte frames, and every one of those readings looks
perfectly periodic. Byte patterns alone cannot settle it.

TCP segment boundaries can. A polling client sends one request and then blocks
for the reply, so each request lands in its own segment — and the capture tells
us exactly where those segments were. That is the primary signal here; byte
patterns are only used to confirm it, or to subdivide a segment when a client
does pipeline several frames into one write.

Hypotheses are tried in order of how much evidence they need:

    text            printable payloads split on a delimiter (SCPI / LXI, which
                    covers a large share of networked lab instruments)
    fixed           every segment is the same length
    length_prefixed a header field states the frame length (Modbus/TCP and many
                    proprietary binary protocols)
    single_segment  honest fallback: one segment is one frame

Pairing requests to responses does not require framing the response stream at
all. In a poll-and-wait loop, "the reply to this request" is simply every byte
the device sent between this request and the next one — which the capture
timestamps give us directly.
"""

from __future__ import annotations

import bisect
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..capture.reassembly import C2S, S2C, StreamChunk

# A frame longer than this is treated as a mis-parse rather than a real frame.
MAX_FRAME_LEN = 65536
# Below this many frames there is not enough repetition to infer anything.
MIN_FRAMES_FOR_INFERENCE = 3
# Fraction of bytes that must be printable before a stream is read as text.
TEXT_PRINTABLE_RATIO = 0.90

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# ----- framing description --------------------------------------------------


@dataclass
class FramingSpec:
    """How to cut a byte stream into frames."""

    mode: str  # "text" | "fixed" | "length_prefixed" | "single_segment"
    frame_len: Optional[int] = None
    delimiter: Optional[bytes] = None
    len_offset: int = 0
    len_size: int = 2
    len_endian: str = "big"
    len_adjust: int = 0  # add to the length field to get the whole frame size
    confidence: float = 0.0
    notes: str = ""

    def describe(self) -> str:
        if self.mode == "text":
            shown = repr(self.delimiter or b"\n").lstrip("b")
            return f"text, delimited by {shown}"
        if self.mode == "fixed":
            return f"fixed {self.frame_len}-byte frames"
        if self.mode == "length_prefixed":
            return (
                f"length field at offset {self.len_offset} "
                f"({self.len_size} bytes, {self.len_endian}-endian, "
                f"{self.len_adjust:+d})"
            )
        return "one frame per TCP segment"

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "frame_len": self.frame_len,
            "delimiter": self.delimiter.hex() if self.delimiter else None,
            "len_offset": self.len_offset,
            "len_size": self.len_size,
            "len_endian": self.len_endian,
            "len_adjust": self.len_adjust,
            "confidence": self.confidence,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FramingSpec":
        delim = d.get("delimiter")
        return cls(
            mode=d["mode"],
            frame_len=d.get("frame_len"),
            delimiter=bytes.fromhex(delim) if delim else None,
            len_offset=d.get("len_offset", 0),
            len_size=d.get("len_size", 2),
            len_endian=d.get("len_endian", "big"),
            len_adjust=d.get("len_adjust", 0),
            confidence=d.get("confidence", 0.0),
            notes=d.get("notes", ""),
        )


@dataclass
class Frame:
    """One protocol frame, with the capture time of its first byte."""

    ts: float
    data: bytes
    stream_offset: int


# ----- timed stream ---------------------------------------------------------


class TimedStream:
    """A reassembled byte stream that remembers when each byte was captured.

    Frame boundaries are found in the concatenated bytes, but every extracted
    frame still needs a real timestamp for the output CSV, so the mapping from
    stream offset back to capture time has to survive.
    """

    def __init__(self) -> None:
        self._data = bytearray()
        self._offsets: List[int] = []
        self._times: List[float] = []
        self.segment_bounds: List[Tuple[int, int, float]] = []  # (start, len, ts)

    def append(self, chunk: StreamChunk) -> None:
        start = len(self._data)
        self._offsets.append(start)
        self._times.append(chunk.ts)
        self.segment_bounds.append((start, len(chunk.data), chunk.ts))
        self._data.extend(chunk.data)

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def ts_at(self, offset: int) -> float:
        """Capture time of the segment that carried the byte at `offset`."""
        if not self._times:
            return 0.0
        i = bisect.bisect_right(self._offsets, offset) - 1
        return self._times[max(0, i)]

    def segment_lengths(self) -> List[int]:
        return [ln for _s, ln, _t in self.segment_bounds if ln > 0]


def build_streams(
    chunks: Sequence[StreamChunk],
) -> Tuple[TimedStream, TimedStream]:
    """Split one flow's chunks into (client->device, device->client) streams."""
    c2s, s2c = TimedStream(), TimedStream()
    for chunk in chunks:
        (c2s if chunk.direction == C2S else s2c).append(chunk)
    return c2s, s2c


# ----- hypotheses -----------------------------------------------------------


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def _try_text(stream: TimedStream) -> Optional[FramingSpec]:
    data = stream.data
    if not data or _printable_ratio(data) < TEXT_PRINTABLE_RATIO:
        return None
    if b"\n" not in data:
        return None
    delimiter = b"\r\n" if data.count(b"\r\n") >= data.count(b"\n") * 0.9 else b"\n"
    if data.count(delimiter) < MIN_FRAMES_FOR_INFERENCE:
        return None
    return FramingSpec(
        mode="text",
        delimiter=delimiter,
        confidence=0.95,
        notes="printable payload with a consistent line terminator",
    )


def _try_fixed(stream: TimedStream) -> Optional[FramingSpec]:
    lengths = stream.segment_lengths()
    if len(lengths) < MIN_FRAMES_FOR_INFERENCE:
        return None
    if len(set(lengths)) != 1:
        return None
    n = lengths[0]
    if not 1 <= n <= MAX_FRAME_LEN:
        return None
    return FramingSpec(
        mode="fixed",
        frame_len=n,
        confidence=0.90,
        notes=f"every one of {len(lengths)} segments was exactly {n} bytes",
    )


def _try_length_prefixed(stream: TimedStream) -> Optional[FramingSpec]:
    """Find a header field that states each segment's own length.

    Fitting against segment boundaries rather than walking the stream means we
    are checking the hypothesis against known-good answers, so a spurious fit
    would have to hold across every segment to survive.
    """
    bounds = [(s, ln) for s, ln, _t in stream.segment_bounds if ln > 0]
    if len(bounds) < MIN_FRAMES_FOR_INFERENCE:
        return None
    if len({ln for _s, ln in bounds}) < 2:
        return None  # constant lengths — "fixed" is the simpler explanation

    data = stream.data
    for size in (2, 4, 1):
        for offset in range(0, 8):
            for endian in ("big", "little"):
                adjust = None
                ok = True
                for start, ln in bounds:
                    if offset + size > ln:
                        ok = False
                        break
                    raw = int.from_bytes(
                        data[start + offset : start + offset + size], endian
                    )
                    this_adjust = ln - raw
                    if adjust is None:
                        adjust = this_adjust
                    elif this_adjust != adjust:
                        ok = False
                        break
                if ok and adjust is not None and -8 <= adjust <= 64:
                    return FramingSpec(
                        mode="length_prefixed",
                        len_offset=offset,
                        len_size=size,
                        len_endian=endian,
                        len_adjust=adjust,
                        confidence=0.85,
                        notes=(
                            f"length field predicted all {len(bounds)} segment "
                            f"sizes exactly"
                        ),
                    )
    return None


def infer_framing(stream: TimedStream) -> FramingSpec:
    """Pick the best-supported framing for one direction of one connection."""
    for hypothesis in (_try_text, _try_fixed, _try_length_prefixed):
        spec = hypothesis(stream)
        if spec is not None:
            return spec
    return FramingSpec(
        mode="single_segment",
        confidence=0.50,
        notes="no repeating structure found; treating each segment as one frame",
    )


# ----- splitting ------------------------------------------------------------


def split_frames(stream: TimedStream, spec: FramingSpec) -> List[Frame]:
    """Cut a stream into frames according to `spec`."""
    data = stream.data
    frames: List[Frame] = []

    if spec.mode == "single_segment":
        for start, ln, ts in stream.segment_bounds:
            if ln:
                frames.append(Frame(ts=ts, data=data[start : start + ln], stream_offset=start))
        return frames

    if spec.mode == "text":
        delim = spec.delimiter or b"\n"
        pos = 0
        while True:
            end = data.find(delim, pos)
            if end < 0:
                break
            end += len(delim)
            frames.append(Frame(ts=stream.ts_at(pos), data=data[pos:end], stream_offset=pos))
            pos = end
        return frames

    if spec.mode == "fixed":
        n = spec.frame_len or 0
        if n <= 0:
            return frames
        for pos in range(0, len(data) - n + 1, n):
            frames.append(Frame(ts=stream.ts_at(pos), data=data[pos : pos + n], stream_offset=pos))
        return frames

    if spec.mode == "length_prefixed":
        pos = 0
        while pos + spec.len_offset + spec.len_size <= len(data):
            head = pos + spec.len_offset
            raw = int.from_bytes(data[head : head + spec.len_size], spec.len_endian)
            total = raw + spec.len_adjust
            if not 1 <= total <= MAX_FRAME_LEN or pos + total > len(data):
                break  # lost alignment; stop rather than emit garbage
            frames.append(
                Frame(ts=stream.ts_at(pos), data=data[pos : pos + total], stream_offset=pos)
            )
            pos += total
        return frames

    return frames


# ----- request / response pairing ------------------------------------------


# A transaction counter has to advance by the same small amount nearly every
# time; these bound what counts as "the same small amount" and "nearly".
MAX_COUNTER_STEP = 16
COUNTER_AGREEMENT = 0.80


def _counter_fields(requests: Sequence[bytes], width: int) -> List[Tuple[int, int]]:
    """Locate transaction counters as whole multi-byte fields.

    Judging each byte on its own is not enough. Over a few hundred requests a
    16-bit counter starting near zero never varies its high byte, so a per-byte
    test masks the low half and leaves the high half in the signature — and then
    a live request whose counter has since rolled past 256 stops matching.

    Reading the field as an integer instead makes the counter obvious: it steps
    by a fixed small amount, wrapping at its width. That identifies the whole
    field, so all of its bytes are excluded together.
    """
    found: List[Tuple[int, int]] = []
    if len(requests) < 4:
        return found
    for size in (4, 2):
        for offset in range(0, width - size + 1):
            if any(o <= offset < o + s for o, s in found):
                continue
            for endian in ("big", "little"):
                modulus = 1 << (8 * size)
                values = [
                    int.from_bytes(r[offset : offset + size], endian) for r in requests
                ]
                steps = [
                    (b - a) % modulus for a, b in zip(values, values[1:])
                ]
                steps = [s for s in steps if 1 <= s <= MAX_COUNTER_STEP]
                if not steps:
                    continue
                modal = max(set(steps), key=steps.count)
                agreement = steps.count(modal) / max(1, len(values) - 1)
                if agreement >= COUNTER_AGREEMENT:
                    found.append((offset, size))
                    break
    return found


def signature_mask(requests: Sequence[bytes]) -> List[bool]:
    """Decide which byte positions of a request identify the channel.

    Grouping responses by the exact request bytes works for a device that polls
    a fixed set of commands, but many protocols put a transaction counter in
    every request — Modbus/TCP does — and then no two requests are ever equal,
    so every sample would land in a channel of its own.

    Two things are excluded: fields that behave like a counter, and single bytes
    that take far too many distinct values to be a channel selector (which
    catches request ids that are random rather than sequential). Masked
    positions are reported to the user rather than hidden, since a genuinely
    wide selector could be masked by mistake on a short capture.
    """
    if not requests:
        return []
    width = len(requests[0])
    n = len(requests)
    limit = max(4, n // 8)

    by_cardinality = [len({req[i] for req in requests}) <= limit for i in range(width)]
    mask = list(by_cardinality)
    for offset, size in _counter_fields(requests, width):
        for i in range(offset, offset + size):
            mask[i] = False

    # A multi-byte counter read at the wrong alignment can reach past its own
    # field — a 16-bit counter followed by zero padding also steps by one when
    # read as a 32-bit value starting a byte later. Usually the extra bytes are
    # padding and masking them costs nothing, but if any of them was the byte
    # that told two channels apart, they would silently merge. Restore whatever
    # is needed to keep as many distinct channels as the cardinality rule saw.
    def distinct(m: Sequence[bool]) -> int:
        return len({apply_mask(r, m) for r in requests})

    target = distinct(by_cardinality)
    if distinct(mask) < target:
        for i in range(width):
            if by_cardinality[i] and not mask[i]:
                mask[i] = True
                if distinct(mask) >= target:
                    break
    return mask


def apply_mask(request: bytes, mask: Sequence[bool]) -> bytes:
    """Blank the varying positions so equal channels compare equal."""
    return bytes(b if keep else 0 for b, keep in zip(request, mask))


@dataclass
class Channel:
    """Every response the device gave to one distinct request.

    A polling client cycles through a fixed set of requests, so grouping
    responses by the request's identifying bytes separates the device's
    measurement channels from one another without knowing anything about the
    protocol.
    """

    signature: bytes
    mask: List[bool] = field(default_factory=list)
    payloads: List[bytes] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)

    @property
    def signature_hex(self) -> str:
        """Hex of the request, with counter-like positions shown as `..`."""
        if not self.signature:
            return "(unsolicited)"
        if not self.mask:
            return self.signature.hex()
        return "".join(
            f"{b:02x}" if keep else ".."
            for b, keep in zip(self.signature, self.mask)
        )

    def matches(self, request: bytes) -> bool:
        """True if a live request belongs to this channel."""
        if len(request) != len(self.signature):
            return False
        if not self.mask:
            return request == self.signature
        return apply_mask(request, self.mask) == self.signature

    @property
    def count(self) -> int:
        return len(self.payloads)

    def median_period(self) -> Optional[float]:
        """Seconds between consecutive samples, as a robust median."""
        if len(self.timestamps) < 2:
            return None
        gaps = [
            b - a
            for a, b in zip(self.timestamps, self.timestamps[1:])
            if b > a
        ]
        return statistics.median(gaps) if gaps else None


@dataclass
class FlowAnalysis:
    """What we worked out about one TCP connection."""

    interaction: str  # "request_response" | "server_push"
    request_spec: Optional[FramingSpec]
    response_spec: Optional[FramingSpec]
    channels: List[Channel]
    request_frames: int = 0
    response_bytes: int = 0
    warnings: List[str] = field(default_factory=list)


def _pair_by_time(
    requests: Sequence[Frame], responses: TimedStream
) -> List[Tuple[Frame, bytes, float]]:
    """Assign to each request the device bytes that arrived before the next one.

    This sidesteps response framing entirely, which matters because a response
    is exactly the thing whose structure we do not yet know.
    """
    segments = [(ts, s, ln) for s, ln, ts in responses.segment_bounds if ln > 0]
    data = responses.data
    paired: List[Tuple[Frame, bytes, float]] = []

    idx = 0
    for i, req in enumerate(requests):
        nxt = requests[i + 1].ts if i + 1 < len(requests) else float("inf")
        while idx < len(segments) and segments[idx][0] < req.ts:
            idx += 1  # arrived before this request: belongs to an earlier one
        collected = bytearray()
        first_ts = None
        j = idx
        while j < len(segments) and segments[j][0] < nxt:
            ts, start, ln = segments[j]
            if first_ts is None:
                first_ts = ts
            collected.extend(data[start : start + ln])
            j += 1
        if collected:
            paired.append((req, bytes(collected), first_ts if first_ts else req.ts))
    return paired


def analyze_flow(chunks: Sequence[StreamChunk]) -> FlowAnalysis:
    """Work out the framing and per-channel samples for one connection."""
    c2s, s2c = build_streams(chunks)
    warnings: List[str] = []

    request_spec = infer_framing(c2s) if len(c2s) else None
    requests = split_frames(c2s, request_spec) if request_spec else []

    # A device that streams unprompted has no requests to group by, so its
    # frames have to be read directly instead.
    if len(requests) < MIN_FRAMES_FOR_INFERENCE:
        response_spec = infer_framing(s2c)
        frames = split_frames(s2c, response_spec)
        channel = Channel(signature=b"")
        for fr in frames:
            channel.payloads.append(fr.data)
            channel.timestamps.append(fr.ts)
        if requests:
            warnings.append(
                f"only {len(requests)} client frames seen; read as a device-push "
                "stream instead of request/response"
            )
        return FlowAnalysis(
            interaction="server_push",
            request_spec=request_spec,
            response_spec=response_spec,
            channels=[channel] if channel.payloads else [],
            request_frames=len(requests),
            response_bytes=len(s2c),
            warnings=warnings,
        )

    # Several requests sharing a timestamp means the client pipelined them into
    # one write, and the time window that separates replies collapses.
    per_ts: Dict[float, int] = {}
    for req in requests:
        per_ts[req.ts] = per_ts.get(req.ts, 0) + 1
    if max(per_ts.values()) > 1:
        warnings.append(
            "client sent multiple frames per segment; response pairing is "
            "less reliable — check the identified signals carefully"
        )

    # Requests of different lengths are different shapes and cannot share a
    # mask, so work out the identifying positions per length.
    by_length: Dict[int, List[bytes]] = {}
    for req in requests:
        by_length.setdefault(len(req.data), []).append(req.data)
    masks = {ln: signature_mask(reqs) for ln, reqs in by_length.items()}
    for ln, mask in masks.items():
        if not all(mask):
            hidden = [i for i, keep in enumerate(mask) if not keep]
            warnings.append(
                f"byte(s) {hidden} of the {ln}-byte request vary like a counter "
                "and were excluded from channel identity"
            )

    grouped: Dict[Tuple[int, bytes], Channel] = {}
    for req, payload, ts in _pair_by_time(requests, s2c):
        mask = masks[len(req.data)]
        signature = apply_mask(req.data, mask)
        key = (len(req.data), signature)
        channel = grouped.get(key)
        if channel is None:
            channel = Channel(signature=signature, mask=list(mask))
            grouped[key] = channel
        channel.payloads.append(payload)
        channel.timestamps.append(ts)

    channels = sorted(grouped.values(), key=lambda c: -c.count)
    if not channels:
        warnings.append("no device replies fell between consecutive requests")

    return FlowAnalysis(
        interaction="request_response",
        request_spec=request_spec,
        response_spec=infer_framing(s2c) if len(s2c) else None,
        channels=channels,
        request_frames=len(requests),
        response_bytes=len(s2c),
        warnings=warnings,
    )


def group_chunks_by_flow(
    chunks: Sequence[StreamChunk],
) -> Dict[object, List[StreamChunk]]:
    """Bucket chunks by connection, preserving capture order within each."""
    flows: Dict[object, List[StreamChunk]] = {}
    for chunk in chunks:
        flows.setdefault(chunk.flow, []).append(chunk)
    return flows
