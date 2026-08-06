"""Synthetic captures for the framing and field-scoring tests.

These build real segments and push them through the real `TCPReassembler`, so a
test exercises the whole path rather than hand-feeding the framer a tidy byte
string. Segment boundaries in particular have to be produced the way a real
poll-and-wait client produces them, because the framer treats them as evidence.

Every generator is deterministic — no RNG seeding to remember, and a failure
reproduces exactly.
"""

from __future__ import annotations

import math
import struct
from typing import Iterable, List, Sequence, Tuple

from lan_sniffer.capture.reassembly import StreamChunk, TCPReassembler

DEVICE_IP = "192.168.0.50"
PEER_IP = "192.168.0.10"
PEER_PORT = 51234

# Exchange = (request_time, request_bytes, response_time, response_bytes)
Exchange = Tuple[float, bytes, float, bytes]


def build_capture(
    exchanges: Sequence[Exchange], device_port: int = 1210
) -> List[StreamChunk]:
    """Replay request/response pairs through the reassembler as TCP segments."""
    asm = TCPReassembler(DEVICE_IP)
    c_seq, s_seq = 1000, 5000
    chunks: List[StreamChunk] = []
    for req_ts, req, resp_ts, resp in exchanges:
        if req:
            chunks += asm.add_segment(
                req_ts, PEER_IP, PEER_PORT, DEVICE_IP, device_port, c_seq, req
            )
            c_seq += len(req)
        if resp:
            chunks += asm.add_segment(
                resp_ts, DEVICE_IP, device_port, PEER_IP, PEER_PORT, s_seq, resp
            )
            s_seq += len(resp)
    return chunks


def build_push_capture(
    frames: Iterable[Tuple[float, bytes]], device_port: int = 4001
) -> List[StreamChunk]:
    """A device that streams without being asked."""
    asm = TCPReassembler(DEVICE_IP)
    seq = 5000
    chunks: List[StreamChunk] = []
    for ts, data in frames:
        chunks += asm.add_segment(
            ts, DEVICE_IP, device_port, PEER_IP, PEER_PORT, seq, data
        )
        seq += len(data)
    return chunks


# ----- signal shapes --------------------------------------------------------


def heat_flow(t: float) -> float:
    """A slow thermal oscillation in mW, like an Angstrom-method run."""
    return 300.0 + 50.0 * math.sin(2.0 * math.pi * t / 261.0)


def temperature(t: float) -> float:
    """A slowly drifting isothermal hold in degrees C."""
    return 150.0 + 0.3 * (t / 3600.0) + 0.01 * math.sin(2.0 * math.pi * t / 37.0)


def furnace_temperature(t: float) -> float:
    """A heating ramp with the overshoot a PID loop leaves behind.

    An isothermal hold is too flat to survive integer scaling — quantised to
    0.1 degrees it is simply constant — so integer-encoded fixtures need a
    channel that genuinely moves.
    """
    return 25.0 + 0.5 * (t / 60.0) + 0.4 * math.sin(2.0 * math.pi * t / 45.0)


# ----- protocol shapes ------------------------------------------------------

# Fixed-length binary, matching the Setaram C80 frames already reverse
# engineered in keithley-smu-control/calorimeter_reader.py: a 6-byte request,
# and a reply that echoes those 6 bytes and appends one big-endian float32.
C80_HF_CMD = bytes.fromhex("0001000a0001")
C80_T_CMD = bytes.fromhex("000100080004")


def c80_capture(n_cycles: int = 120, period: float = 1.0) -> List[StreamChunk]:
    """Alternating heat-flow and temperature polls, C80 frame layout."""
    exchanges: List[Exchange] = []
    t = 0.0
    for _ in range(n_cycles):
        for cmd, value in (
            (C80_HF_CMD, heat_flow(t)),
            (C80_T_CMD, temperature(t)),
        ):
            reply = cmd + struct.pack(">f", value)
            exchanges.append((t, cmd, t + 0.012, reply))
            t += period / 2.0
    return build_capture(exchanges)


def modbus_capture(n_cycles: int = 120, period: float = 1.0) -> List[StreamChunk]:
    """Modbus/TCP: an MBAP length header and a per-request transaction id.

    The transaction id is what makes this a useful fixture — it is different in
    every single request, so channel grouping has to ignore it.
    """
    exchanges: List[Exchange] = []
    txid = 0
    t = 0.0
    # (register address, register count, value function, scale)
    polls = (
        (0x0010, 2, lambda tt: int(round(furnace_temperature(tt) * 10))),
        (0x0020, 3, lambda tt: int(round(heat_flow(tt) * 10))),
    )
    for _ in range(n_cycles):
        for addr, count, valfn in polls:
            pdu = struct.pack(">BHH", 0x03, addr, count)
            req = struct.pack(">HHHB", txid, 0, len(pdu) + 1, 0x01) + pdu
            data = struct.pack(">H", valfn(t) & 0xFFFF) + b"\x00\x00" * (count - 1)
            rpdu = struct.pack(">BB", 0x03, len(data)) + data
            resp = struct.pack(">HHHB", txid, 0, len(rpdu) + 1, 0x01) + rpdu
            exchanges.append((t, req, t + 0.008, resp))
            txid = (txid + 1) & 0xFFFF
            t += period / 2.0
    return build_capture(exchanges, device_port=502)


def length_prefixed_capture(
    n_cycles: int = 120, period: float = 1.0
) -> List[StreamChunk]:
    """A proprietary binary protocol whose commands genuinely vary in length.

    Modbus read requests are all the same size, so they are correctly described
    as fixed-length and never exercise the length-prefix path. This shape — a
    magic word, a 16-bit body length, then a variable body — is the common
    proprietary layout that does need it.
    """
    exchanges: List[Exchange] = []
    t = 0.0
    polls = (
        (b"\x01\x02", heat_flow),
        (b"\x07", temperature),
        (b"\x03\x04\x05\x06", lambda tt: heat_flow(tt) * 0.5),
    )
    for _ in range(n_cycles):
        for body, valfn in polls:
            req = b"\xab\xcd" + struct.pack(">H", len(body)) + body
            payload = struct.pack(">f", valfn(t))
            resp = b"\xab\xcd" + struct.pack(">H", len(payload)) + payload
            exchanges.append((t, req, t + 0.009, resp))
            t += period / 3.0
    return build_capture(exchanges, device_port=9100)


def scpi_capture(n_cycles: int = 120, period: float = 1.0) -> List[StreamChunk]:
    """SCPI over TCP: printable commands and replies, newline terminated."""
    exchanges: List[Exchange] = []
    t = 0.0
    for _ in range(n_cycles):
        for cmd, value in (
            (b"MEAS:TEMP?\n", temperature(t)),
            (b"MEAS:HEAT?\n", heat_flow(t)),
        ):
            reply = ("%+.5E\n" % value).encode("ascii")
            exchanges.append((t, cmd, t + 0.010, reply))
            t += period / 2.0
    return build_capture(exchanges, device_port=5025)


def push_capture(n_samples: int = 200, period: float = 0.5) -> List[StreamChunk]:
    """An unprompted stream of 8-byte frames carrying two big-endian floats."""
    frames = []
    for i in range(n_samples):
        t = i * period
        frames.append(
            (t, struct.pack(">ff", heat_flow(t), temperature(t)))
        )
    return build_push_capture(frames)
