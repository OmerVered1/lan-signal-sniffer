# READ-ONLY MODULE
"""Ask an instrument directly, for the case where watching it is not enough.

Everything else in this app is passive, because the instruments it was built for
accept a single TCP client and connecting would take it from the software
running the experiment. This module is the deliberate exception, and it is
narrow: it exists for an instrument whose software is **closed**, where there is
no client to displace and no experiment to interrupt.

It came out of a MAX300 mass spectrometer. Four hours of its traffic, 58
channels, every offset and encoding: nothing decodes into the ion-current range,
and its two large arrays correlate at 0.26 and -0.00 between sweeps 2.6 seconds
apart, so they are detector noise and not a repeatable spectrum. The published
values are computed in the vendor software and written to a file. Watching that
link therefore cannot produce them, and the only remaining question is what the
analyser will say if it is asked.

Two rules keep the asking honest:

  * **Nothing is invented.** Every request sent is one observed in a capture, or
    an observed request with a single field changed. The app does not guess at
    an opcode it has never seen an instrument accept.
  * **Reads only, by evidence.** A request the vendor software repeated at a
    steady cadence for hours is a poll. One sent once, at startup, might be a
    write that configures something — so those are excluded by default and have
    to be asked for by name.

Neither rule makes this safe in the way passive capture is safe. It is a
different trade, taken for a reason, in a situation the user chose.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..capture.reassembly import C2S, StreamChunk
from ..protocol.framer import analyze_flow, group_chunks_by_flow

# A request seen fewer times than this over a whole capture was not a poll, and
# might be a write. Excluded unless explicitly named.
POLL_THRESHOLD = 20
# Nothing is sent faster than this, so a scan cannot flood an instrument.
MIN_INTERVAL_S = 0.02
DEFAULT_TIMEOUT_S = 3.0


@dataclass
class ObservedRequest:
    """One request the vendor software actually sent, and what came back."""

    payload: bytes
    count: int
    reply_sizes: Dict[int, int] = field(default_factory=dict)

    @property
    def opcode(self) -> int:
        return self.payload[0] if self.payload else -1

    @property
    def is_poll(self) -> bool:
        """Repeated steadily, so the vendor software treated it as a read."""
        return self.count >= POLL_THRESHOLD

    @property
    def largest_reply(self) -> int:
        return max(self.reply_sizes, default=0)

    def words(self) -> List[int]:
        """The request as little-endian 32-bit words, which is how it is built."""
        return [
            int.from_bytes(self.payload[i : i + 4], "little")
            for i in range(0, len(self.payload) - 3, 4)
        ]

    def with_word(self, index: int, value: int) -> bytes:
        """The same request with one 32-bit field changed, and nothing else."""
        if not 0 <= index * 4 + 4 <= len(self.payload):
            raise ValueError(f"word {index} is outside a {len(self.payload)}-byte request")
        out = bytearray(self.payload)
        out[index * 4 : index * 4 + 4] = int(value).to_bytes(4, "little")
        return bytes(out)

    def describe(self) -> str:
        words = " ".join(f"{w:08x}" for w in self.words())
        kind = "poll" if self.is_poll else "seen once or twice"
        return (
            f"{words}  ({len(self.payload)}B, sent {self.count}x, {kind}, "
            f"replies up to {self.largest_reply}B)"
        )


def observed_requests(
    chunks: Sequence[StreamChunk], device_ip: str = ""
) -> List[ObservedRequest]:
    """Collect the distinct requests one device was sent, with their replies.

    Uses the app's own framing so that what can be replayed is exactly what was
    recorded — a request reconstructed some other way might differ in a byte
    that matters and would be a guess wearing the costume of evidence.
    """
    wanted = [
        c for c in chunks if not device_ip or c.device_ip in ("", device_ip)
    ]
    found: Dict[bytes, ObservedRequest] = {}
    for flow_chunks in group_chunks_by_flow(wanted).values():
        analysis = analyze_flow(flow_chunks)
        for channel in analysis.channels:
            entry = found.setdefault(
                channel.signature, ObservedRequest(payload=channel.signature, count=0)
            )
            entry.count += len(channel.payloads)
            for payload in channel.payloads:
                n = len(payload)
                entry.reply_sizes[n] = entry.reply_sizes.get(n, 0) + 1
    return sorted(found.values(), key=lambda r: -r.count)


def opening_sequence(
    chunks: Sequence[StreamChunk], device_ip: str = "", limit_bytes: int = 4096
) -> List[bytes]:
    """The first thing the vendor software says on a fresh connection.

    An instrument can accept a TCP connection and then answer nothing at all
    until it has been greeted — a login, a protocol version, a session open.
    That greeting is sent once per connection, so it is invisible to anything
    that looks for repeated polls, and it is missing entirely from a capture
    that began while the software was already connected.

    Recognising it needs a capture that starts *before* the vendor software
    does. What identifies it is the stream offset: byte zero of the
    client-to-server direction is the first thing ever said on that connection,
    whatever it turns out to mean.

    Returns the opening client frames in order, or an empty list when the
    capture joined a conversation already in progress — which is not the same
    answer as "there is no handshake", and the caller has to say so.
    """
    wanted = [
        c
        for c in chunks
        if c.direction == C2S
        and (not device_ip or c.device_ip in ("", device_ip))
        and c.stream_offset < limit_bytes
    ]
    if not any(c.stream_offset == 0 for c in wanted):
        return []
    wanted.sort(key=lambda c: (c.stream_offset, c.ts))
    out: List[bytes] = []
    seen = set()
    for chunk in wanted:
        if chunk.stream_offset in seen:
            continue
        seen.add(chunk.stream_offset)
        out.append(chunk.data)
    return out


@dataclass
class ProbeReply:
    request: bytes
    reply: bytes
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.reply)


class Probe:
    """A single TCP conversation with an instrument, one request at a time.

    Deliberately synchronous and un-pipelined: send one, read the reply, stop.
    An instrument that accepts one client is not one to be clever with, and a
    reply that cannot be attributed to its request is worth nothing anyway.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        quiet_ms: int = 250,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        # How long the reply must stay silent before it is considered finished.
        # There is no length prefix to rely on, so the end of a reply is only
        # ever inferred from a pause.
        self.quiet_s = quiet_ms / 1000.0
        self._sock: Optional[socket.socket] = None

    def __enter__(self) -> "Probe":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        self._sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout_s
        )

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def ask(self, request: bytes) -> ProbeReply:
        if self._sock is None:
            return ProbeReply(request, b"", "not connected")
        try:
            self._sock.sendall(request)
        except OSError as e:
            return ProbeReply(request, b"", f"send failed: {e}")

        chunks: List[bytes] = []
        self._sock.settimeout(self.timeout_s)
        try:
            first = self._sock.recv(65536)
            if not first:
                return ProbeReply(request, b"", "connection closed by the instrument")
            chunks.append(first)
            # Drain whatever follows until it goes quiet: a 24 KB reply arrives
            # as many segments and there is no length to count down.
            self._sock.settimeout(self.quiet_s)
            while True:
                more = self._sock.recv(65536)
                if not more:
                    break
                chunks.append(more)
        except socket.timeout:
            pass
        except OSError as e:
            return ProbeReply(request, b"".join(chunks), f"receive failed: {e}")
        return ProbeReply(request, b"".join(chunks))
