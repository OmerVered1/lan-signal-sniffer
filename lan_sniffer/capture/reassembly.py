# READ-ONLY MODULE
"""Per-connection, per-direction TCP stream reassembly.

This is deliberately not a full TCP stack. We capture on the same host as one
endpoint, so we see every segment, essentially always in order. What this class
must get right is the small set of things that do happen in practice:
retransmissions, brief reordering, and segments that split a protocol frame
across packet boundaries.

One property matters more than it looks: **segment boundaries are preserved**.
Each emitted `StreamChunk` corresponds to exactly one TCP segment. The framing
inference in `lan_sniffer.protocol.framer` leans on those boundaries as its
primary signal, because a poll-and-wait client emits one request per segment and
then blocks for the reply. Guessing frame length from byte patterns alone is
ambiguous (a stream of 6-byte frames also parses cleanly as 3-byte or 2-byte
frames); the segment boundary is ground truth. Do not coalesce chunks here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Direction labels. "c2s" is client -> device (the polling request), "s2c" is
# device -> client (the reply carrying the measurements).
C2S = "c2s"
S2C = "s2c"

_SEQ_MOD = 1 << 32
_SEQ_HALF = 1 << 31

# Bounds on the out-of-order buffer. A lab poll loop is a few hundred bytes per
# second, so these are generous; they exist only so a pathological capture can't
# grow the process without limit.
MAX_PENDING_SEGMENTS = 64
MAX_PENDING_BYTES = 256 * 1024


def _seq_lt(a: int, b: int) -> bool:
    """True if sequence number `a` precedes `b`, accounting for 32-bit wrap."""
    return ((b - a) % _SEQ_MOD) < _SEQ_HALF and a != b


def _seq_diff(a: int, b: int) -> int:
    """Signed distance a - b on the 32-bit sequence circle."""
    d = (a - b) % _SEQ_MOD
    return d - _SEQ_MOD if d >= _SEQ_HALF else d


@dataclass(frozen=True)
class FlowKey:
    """Identifies one TCP connection by its non-device endpoint.

    The device side of the conversation is fixed for a given capture, so the
    peer's (ip, port) is enough to tell connections apart, and it stays stable
    if the vendor software reconnects on a new local port.
    """

    peer_ip: str
    peer_port: int
    device_port: int

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.peer_ip}:{self.peer_port}->:{self.device_port}"


@dataclass
class StreamChunk:
    """One TCP segment's payload, placed in its stream.

    `stream_offset` is the byte position of `data[0]` within this direction's
    reassembled stream, counting from the first byte we observed. `gap_before`
    is set when bytes were lost ahead of this chunk (capture drop or a stretch
    we gave up waiting for), which tells downstream decoders that frame
    alignment may have been broken.
    """

    ts: float
    flow: FlowKey
    direction: str
    data: bytes
    stream_offset: int
    gap_before: int = 0


@dataclass
class _DirState:
    """Reassembly state for one direction of one connection."""

    next_seq: Optional[int] = None
    stream_offset: int = 0
    pending: Dict[int, Tuple[float, bytes]] = field(default_factory=dict)
    pending_bytes: int = 0


class TCPReassembler:
    """Turns captured TCP segments into ordered per-direction byte streams.

    Construct with the monitored device's IP; direction is derived from it, so
    callers don't have to work out which side is the client.

    `add_segment` returns the chunks that became deliverable as a result of this
    segment — usually exactly one, occasionally several when a reordering
    resolves, and none when the segment is a pure retransmission or is buffered
    waiting for a hole to fill.
    """

    def __init__(self, device_ip: str) -> None:
        self._device_ip = device_ip
        self._flows: Dict[Tuple[FlowKey, str], _DirState] = {}

    # ----- public API ------------------------------------------------------

    def add_segment(
        self,
        ts: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        payload: bytes,
        syn: bool = False,
        fin: bool = False,
        rst: bool = False,
    ) -> List[StreamChunk]:
        if src_ip == self._device_ip:
            direction = S2C
            flow = FlowKey(peer_ip=dst_ip, peer_port=dst_port, device_port=src_port)
        elif dst_ip == self._device_ip:
            direction = C2S
            flow = FlowKey(peer_ip=src_ip, peer_port=src_port, device_port=dst_port)
        else:
            # Not our device. The kernel BPF filter should have excluded this,
            # but a caller replaying a mixed capture might not have.
            return []

        key = (flow, direction)
        state = self._flows.get(key)
        if state is None:
            state = _DirState()
            self._flows[key] = state

        if syn:
            # A fresh connection resets the stream: the vendor software has
            # reconnected, so any half-parsed frame from before is meaningless.
            state.next_seq = (seq + 1) % _SEQ_MOD
            state.pending.clear()
            state.pending_bytes = 0

        chunks: List[StreamChunk] = []
        if payload:
            chunks = self._accept(state, flow, direction, ts, seq, payload)

        if fin or rst:
            # Drop anything still waiting behind a hole; it will never arrive.
            state.pending.clear()
            state.pending_bytes = 0
            state.next_seq = None

        return chunks

    def close_flow(self, flow: FlowKey) -> None:
        """Forget both directions of a connection."""
        for direction in (C2S, S2C):
            self._flows.pop((flow, direction), None)

    def active_flows(self) -> List[FlowKey]:
        seen: List[FlowKey] = []
        for flow, _direction in self._flows:
            if flow not in seen:
                seen.append(flow)
        return seen

    # ----- internals -------------------------------------------------------

    def _accept(
        self,
        state: _DirState,
        flow: FlowKey,
        direction: str,
        ts: float,
        seq: int,
        payload: bytes,
    ) -> List[StreamChunk]:
        if state.next_seq is None:
            # Mid-stream attach: we started capturing after the vendor software
            # was already connected, which is the normal case. Adopt whatever
            # sequence number we first see as the origin of the stream.
            state.next_seq = seq

        chunks: List[StreamChunk] = []
        gap = self._deliver(state, flow, direction, ts, seq, payload, chunks, gap=0)
        if gap:
            # Nothing was delivered; the segment went into the pending buffer.
            pass
        self._drain(state, flow, direction, chunks)
        self._enforce_pending_limits(state, flow, direction, chunks)
        return chunks

    def _deliver(
        self,
        state: _DirState,
        flow: FlowKey,
        direction: str,
        ts: float,
        seq: int,
        payload: bytes,
        chunks: List[StreamChunk],
        gap: int,
    ) -> bool:
        """Place one segment. Returns True if it was buffered rather than emitted."""
        assert state.next_seq is not None
        end = (seq + len(payload)) % _SEQ_MOD

        if not _seq_lt(state.next_seq, end) and end != state.next_seq:
            # Wholly in the past: a plain retransmission of data we already have.
            return False
        if end == state.next_seq:
            return False

        if _seq_lt(seq, state.next_seq):
            # Partial overlap: trim the prefix we have already delivered.
            skip = _seq_diff(state.next_seq, seq)
            payload = payload[skip:]
            seq = state.next_seq
            if not payload:
                return False

        if seq != state.next_seq:
            # Ahead of the hole — hold it until the missing bytes show up.
            if seq not in state.pending:
                state.pending[seq] = (ts, payload)
                state.pending_bytes += len(payload)
            return True

        chunks.append(
            StreamChunk(
                ts=ts,
                flow=flow,
                direction=direction,
                data=payload,
                stream_offset=state.stream_offset,
                gap_before=gap,
            )
        )
        state.stream_offset += len(payload)
        state.next_seq = (seq + len(payload)) % _SEQ_MOD
        return False

    def _drain(
        self,
        state: _DirState,
        flow: FlowKey,
        direction: str,
        chunks: List[StreamChunk],
    ) -> None:
        """Emit buffered segments that the latest delivery made contiguous."""
        while state.pending:
            nxt = state.next_seq
            entry = state.pending.pop(nxt, None)
            if entry is None:
                # Also accept a buffered segment that merely overlaps the front.
                candidate = None
                for pseq in state.pending:
                    if _seq_lt(pseq, nxt):
                        candidate = pseq
                        break
                if candidate is None:
                    return
                entry = state.pending.pop(candidate)
                nxt = candidate
            ts, payload = entry
            state.pending_bytes -= len(payload)
            self._deliver(state, flow, direction, ts, nxt, payload, chunks, gap=0)

    def _enforce_pending_limits(
        self,
        state: _DirState,
        flow: FlowKey,
        direction: str,
        chunks: List[StreamChunk],
    ) -> None:
        """Give up on an unfillable hole rather than buffer without bound.

        When we skip forward we report the size of the lost run via
        `gap_before`, so a decoder can resynchronise instead of silently
        emitting misaligned frames.
        """
        while (
            len(state.pending) > MAX_PENDING_SEGMENTS
            or state.pending_bytes > MAX_PENDING_BYTES
        ):
            assert state.next_seq is not None
            earliest = min(state.pending, key=lambda s: _seq_diff(s, state.next_seq))
            gap = _seq_diff(earliest, state.next_seq)
            ts, payload = state.pending.pop(earliest)
            state.pending_bytes -= len(payload)
            state.next_seq = earliest
            state.stream_offset += max(0, gap)
            self._deliver(
                state, flow, direction, ts, earliest, payload, chunks, gap=max(0, gap)
            )
            self._drain(state, flow, direction, chunks)
