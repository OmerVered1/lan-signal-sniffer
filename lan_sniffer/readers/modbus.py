"""Modbus client, for reading values an instrument publishes on request.

Questor5 can act as a Modbus slave and place its analysis results in holding
registers, which is how a process analyser is normally wired into a plant
control system. Reading those registers gives the numbers the software itself
computed, exactly, rather than anything reconstructed from raw detector data.

Two framings are supported because the vendor dialog offers a choice and
getting it wrong looks identical to a dead link:

    rtu_tcp   RTU frames — unit, function, data, CRC16 — carried over TCP.
              This is what Questor5 calls "RTU-TCP".
    tcp       Standard Modbus TCP: an MBAP header with a transaction id and a
              length, and no CRC.

Three register formats are supported, matching the three the manual documents.
`ieee754` is the one to prefer: it carries a plain 32-bit float and needs no
duplicated configuration, while `single` requires the reader to hold an exact
copy of the scale limits set in the vendor software and silently returns wrong
numbers if they ever drift apart.

The protocol layer here is pure — frames in, frames out — so it can be tested
without a network, and against the worked examples printed in the manual.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

READ_HOLDING_REGISTERS = 0x03
READ_INPUT_REGISTERS = 0x04

# The divisor Questor5 uses for its legacy paired format, and the factor it
# multiplies a percentage by before splitting it.
LEGACY_DIVISOR = 32767
LEGACY_FACTOR = 1_000_000

FORMATS = ("ieee754", "legacy_paired", "single", "uint16", "int16")

EXCEPTIONS = {
    0x01: "illegal function",
    0x02: "illegal data address — check the register address in the profile",
    0x03: "illegal data value",
    0x04: "slave device failure",
    0x06: "slave device busy",
}


class ModbusError(RuntimeError):
    """A protocol-level failure: a bad frame, or an exception from the slave."""


def crc16(data: bytes) -> int:
    """Modbus CRC-16, transmitted low byte first."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


# ----- framing --------------------------------------------------------------


def build_request(
    unit: int,
    address: int,
    count: int,
    framing: str = "rtu_tcp",
    function: int = READ_HOLDING_REGISTERS,
    transaction: int = 1,
) -> bytes:
    """One read request, in whichever framing the slave expects."""
    body = struct.pack(">BBHH", unit, function, address, count)
    if framing == "rtu_tcp":
        return body + struct.pack("<H", crc16(body))
    if framing == "tcp":
        # MBAP: transaction, protocol 0, length of what follows, then the body.
        return struct.pack(">HHH", transaction, 0, len(body)) + body
    raise ValueError(f"unknown framing {framing!r}")


def expected_length(count: int, framing: str) -> int:
    """Bytes in a well-formed reply to a read of `count` registers."""
    payload = 3 + count * 2  # unit, function, byte count, data
    return payload + (2 if framing == "rtu_tcp" else 0) + (6 if framing == "tcp" else 0)


def parse_response(
    data: bytes, framing: str = "rtu_tcp", function: int = READ_HOLDING_REGISTERS
) -> List[int]:
    """Pull the register values out of a reply, or raise saying why not."""
    if framing == "tcp":
        if len(data) < 8:
            raise ModbusError(f"reply too short for Modbus TCP ({len(data)} bytes)")
        _txid, protocol, length = struct.unpack(">HHH", data[:6])
        if protocol != 0:
            raise ModbusError(f"not a Modbus TCP reply (protocol id {protocol})")
        frame = data[6 : 6 + length]
    elif framing == "rtu_tcp":
        if len(data) < 5:
            raise ModbusError(f"reply too short for Modbus RTU ({len(data)} bytes)")
        frame, checksum = data[:-2], struct.unpack("<H", data[-2:])[0]
        if crc16(frame) != checksum:
            raise ModbusError(
                "CRC mismatch — the slave may be speaking plain Modbus TCP "
                "rather than RTU-TCP; try the other framing"
            )
    else:
        raise ValueError(f"unknown framing {framing!r}")

    if len(frame) < 2:
        raise ModbusError("truncated reply")
    _unit, code = frame[0], frame[1]
    if code & 0x80:
        reason = EXCEPTIONS.get(frame[2] if len(frame) > 2 else 0, "unknown")
        raise ModbusError(f"slave returned exception: {reason}")
    if code != function:
        raise ModbusError(f"expected function {function}, got {code}")

    byte_count = frame[2]
    values = frame[3 : 3 + byte_count]
    if len(values) < byte_count:
        raise ModbusError("reply shorter than its own byte count")
    return [
        struct.unpack(">H", values[i : i + 2])[0] for i in range(0, byte_count - 1, 2)
    ]


# ----- register formats -----------------------------------------------------


def decode_ieee754(high: int, low: int, word_swap: bool = False) -> float:
    """Two registers holding one 32-bit float.

    Word order is not settled by the standard and vendors differ, so it is a
    setting rather than an assumption: read the wrong way round the value is
    not merely inaccurate, it is nonsense.
    """
    a, b = (low, high) if word_swap else (high, low)
    return struct.unpack(">f", struct.pack(">HH", a, b))[0]


def decode_legacy_paired(high: int, low: int) -> float:
    """Questor5's legacy pair: quotient and remainder of value x 1e6 / 32767.

    The manual's worked example is 42.1466%, stored as 1286 and 8238.
    """
    return (high * LEGACY_DIVISOR + low) / LEGACY_FACTOR


def decode_single(stored: int, scale_lo: float, scale_hi: float, full_scale: int) -> float:
    """One register holding a percentage of the span between two limits.

    The reader has to hold an exact copy of the limits configured in the vendor
    software. If they are ever changed on one side only this returns wrong
    numbers with no indication, which is why `ieee754` is the better choice.
    """
    if full_scale == 0:
        raise ValueError("full scale cannot be zero")
    return scale_lo + (stored / full_scale) * (scale_hi - scale_lo)


@dataclass
class RegisterSpec:
    """One value to read: where it lives and how it is stored."""

    name: str
    address: int
    format: str = "ieee754"
    unit: str = ""
    word_swap: bool = False
    scale_lo: float = 0.0
    scale_hi: float = 100.0
    full_scale: int = 9999
    scale: float = 1.0
    bias: float = 0.0

    @property
    def registers(self) -> int:
        return 2 if self.format in ("ieee754", "legacy_paired") else 1

    def decode(self, words: Sequence[int]) -> float:
        if self.format == "ieee754":
            raw = decode_ieee754(words[0], words[1], self.word_swap)
        elif self.format == "legacy_paired":
            raw = decode_legacy_paired(words[0], words[1])
        elif self.format == "single":
            raw = decode_single(words[0], self.scale_lo, self.scale_hi, self.full_scale)
        elif self.format == "uint16":
            raw = float(words[0])
        elif self.format == "int16":
            raw = float(struct.unpack(">h", struct.pack(">H", words[0]))[0])
        else:
            raise ValueError(f"unknown register format {self.format!r}")
        return raw * self.scale + self.bias

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": self.address,
            "format": self.format,
            "unit": self.unit,
            "word_swap": self.word_swap,
            "scale_lo": self.scale_lo,
            "scale_hi": self.scale_hi,
            "full_scale": self.full_scale,
            "scale": self.scale,
            "bias": self.bias,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RegisterSpec":
        return cls(
            name=d["name"],
            address=int(d["address"]),
            format=d.get("format", "ieee754"),
            unit=d.get("unit", ""),
            word_swap=bool(d.get("word_swap", False)),
            scale_lo=float(d.get("scale_lo", 0.0)),
            scale_hi=float(d.get("scale_hi", 100.0)),
            full_scale=int(d.get("full_scale", 9999)),
            scale=float(d.get("scale", 1.0)),
            bias=float(d.get("bias", 0.0)),
        )


def plan_reads(
    registers: Sequence[RegisterSpec], max_span: int = 120
) -> List[Tuple[int, int]]:
    """Group registers into as few reads as possible.

    Contiguous or nearby addresses are fetched together: seven separate round
    trips to an instrument several seconds' walk away would sample the values
    at visibly different moments, which matters when they are meant to describe
    one gas composition.
    """
    if not registers:
        return []
    spans = sorted((r.address, r.address + r.registers) for r in registers)
    reads: List[Tuple[int, int]] = []
    start, end = spans[0]
    for lo, hi in spans[1:]:
        if hi - start <= max_span:
            end = max(end, hi)
        else:
            reads.append((start, end - start))
            start, end = lo, hi
    reads.append((start, end - start))
    return reads


# ----- the client -----------------------------------------------------------


class ModbusClient:
    """Reads a set of registers from a slave, over TCP.

    Connects lazily and keeps the socket, because a process analyser is polled
    every few seconds for hours and reconnecting each time would be both slower
    and noisier in the slave's own logs.
    """

    def __init__(
        self,
        host: str,
        port: int = 502,
        unit: int = 1,
        framing: str = "rtu_tcp",
        timeout: float = 3.0,
        function: int = READ_HOLDING_REGISTERS,
    ) -> None:
        self.host = host
        self.port = port
        self.unit = unit
        self.framing = framing
        self.timeout = timeout
        self.function = function
        self._socket: Optional[socket.socket] = None
        self._transaction = 0

    # ----- connection ---------------------------------------------------

    def connect(self) -> None:
        if self._socket is not None:
            return
        self._socket = socket.create_connection((self.host, self.port), self.timeout)
        self._socket.settimeout(self.timeout)

    def close(self) -> None:
        sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    @property
    def connected(self) -> bool:
        return self._socket is not None

    def __enter__(self) -> "ModbusClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ----- reading ------------------------------------------------------

    def _exchange(self, address: int, count: int) -> List[int]:
        self.connect()
        assert self._socket is not None
        self._transaction = (self._transaction + 1) & 0xFFFF
        request = build_request(
            self.unit,
            address,
            count,
            framing=self.framing,
            function=self.function,
            transaction=self._transaction,
        )
        self._socket.sendall(request)

        wanted = expected_length(count, self.framing)
        buffer = b""
        while len(buffer) < wanted:
            chunk = self._socket.recv(wanted - len(buffer))
            if not chunk:
                raise ModbusError("the slave closed the connection")
            buffer += chunk
        return parse_response(buffer, self.framing, self.function)

    def read(self, registers: Sequence[RegisterSpec]) -> Dict[str, float]:
        """Read every register and return the decoded values by name.

        A value whose own decoding fails is left out rather than allowed to
        abort the others: one badly configured entry should not cost the whole
        reading.
        """
        if not registers:
            return {}
        words: Dict[int, int] = {}
        for address, count in plan_reads(registers):
            for i, word in enumerate(self._exchange(address, count)):
                words[address + i] = word

        out: Dict[str, float] = {}
        for spec in registers:
            needed = [words.get(spec.address + i) for i in range(spec.registers)]
            if any(w is None for w in needed):
                continue
            try:
                out[spec.name] = spec.decode([int(w) for w in needed])
            except (ValueError, struct.error):
                continue
        return out
