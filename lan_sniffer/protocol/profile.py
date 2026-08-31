# READ-ONLY MODULE
"""Device profiles: what the user decided a device's bytes mean.

A profile is the output of the identification wizard and the input to live
recording. It is deliberately a plain JSON file with no code in it — the
decoding engine has no per-device branches, so a profile for the C80 is the
same kind of object as a profile for a device nobody has ever decoded. The two
profiles shipped in `profiles/` were seeded from command bytes already verified
on the bench, but they hold no privileged status.

`LiveDecoder` applies a profile to traffic as it arrives. It pairs requests with
replies the same way the offline analysis does — a reply is whatever the device
sent before the next request went out — so what gets recorded matches what the
user approved in the wizard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..capture.reassembly import C2S, S2C, StreamChunk
from ..readers.modbus import FORMATS as MODBUS_FORMATS, RegisterSpec
from .fields import ENCODINGS, decode_field
from .framer import FramingSpec, TimedStream, apply_mask, split_frames

PROFILE_VERSION = 2

# Where a device's values come from.
SOURCE_SNIFF = "sniff"    # watch the vendor software's traffic, decode replies
SOURCE_MODBUS = "modbus"  # ask the instrument's own Modbus slave for them


# Byte width of each encoding, for working out how many records fit in a reply.
_ENC_WIDTH: Dict[str, int] = {name: size for name, _dt, size, _f in ENCODINGS}


@dataclass
class SignalSpec:
    """One named, unit-bearing quantity the user chose to record."""

    name: str
    unit: str
    signature: bytes  # the request that asks for it, counter bytes blanked
    mask: List[bool]
    offset: int
    encoding: str
    scale: float = 1.0
    bias: float = 0.0
    # Bytes from one record of this field to the next inside a single reply.
    # Zero means one reading per reply, which is the ordinary case.
    #
    # Some instruments buffer. When the software logs faster than it polls, the
    # instrument answers with every reading taken since the last request, packed
    # back to back. A Setaram oven logging at 10 Hz and polled at 1 Hz replies
    # with ten records in one frame, and a decoder that reads only the first
    # throws nine tenths of the experiment away without any sign that it did.
    stride: int = 0
    # Bytes before the first record - the reply's own header. Only meaningful
    # alongside a stride, and what makes it possible to tell a clean batch from
    # a damaged one: a whole number of records must fit between the header and
    # the end of the reply.
    record_base: int = 0

    def matches(self, request: bytes) -> bool:
        if len(request) != len(self.signature):
            return False
        if not self.mask:
            return request == self.signature
        return apply_mask(request, self.mask) == self.signature

    def convert(self, raw: float) -> float:
        return raw * self.scale + self.bias

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "unit": self.unit,
            "signature": self.signature.hex(),
            "mask": [bool(m) for m in self.mask],
            "offset": self.offset,
            "encoding": self.encoding,
            "scale": self.scale,
            "bias": self.bias,
            "stride": self.stride,
            "record_base": self.record_base,
        }

    def width(self) -> int:
        """Bytes this field occupies, for working out how many records fit."""
        if self.encoding.startswith("ascii"):
            return 0
        return _ENC_WIDTH.get(self.encoding, 0)

    def record_count(self, payload_len: int) -> int:
        """How many readings of this field a reply of this length carries.

        A batch is only read as a batch when the reply divides exactly into
        records. Two replies concatenated - which happens when a request goes
        unseen and the pairing lumps the answers together - put a second header
        in the middle and shift every record after it, and reading straight
        through produces plausible-looking numbers that are wrong. So an
        unaligned reply falls back to its first record, which is the one that
        is always where it claims to be.

        Losing the rest costs a fraction of a second of a run. Emitting them
        wrong costs more than that, and silently.
        """
        if self.stride <= 0:
            return 1
        if self.offset + self.width() > payload_len:
            return 0
        if self.record_base or self.record_base == 0:
            span = payload_len - self.record_base
            if span > 0 and span % self.stride == 0:
                return span // self.stride
        return 1

    @classmethod
    def from_dict(cls, d: dict) -> "SignalSpec":
        return cls(
            name=d["name"],
            unit=d.get("unit", ""),
            signature=bytes.fromhex(d.get("signature", "")),
            mask=[bool(m) for m in d.get("mask", [])],
            offset=int(d["offset"]),
            encoding=d["encoding"],
            scale=float(d.get("scale", 1.0)),
            bias=float(d.get("bias", 0.0)),
            stride=int(d.get("stride", 0)),
            record_base=int(d.get("record_base", 0)),
        )


@dataclass
class DeviceProfile:
    """Everything needed to turn one device's traffic back into measurements."""

    name: str
    device_port: int
    request_framing: FramingSpec
    signals: List[SignalSpec] = field(default_factory=list)
    interaction: str = "request_response"
    # Most instruments are sniffed. One that computes its published numbers in
    # software never puts them on the wire, and no amount of watching recovers
    # them — but it may offer them through a Modbus slave, which exists to be
    # asked. Such a device is read rather than watched.
    source: str = SOURCE_SNIFF
    modbus: dict = field(default_factory=dict)
    registers: List["RegisterSpec"] = field(default_factory=list)
    # Only needed for devices that stream unprompted: with no request to pair
    # against, the reply stream has to be framed on its own.
    response_framing: Optional[FramingSpec] = None
    mac: str = ""
    ip_hint: str = ""
    session: dict = field(default_factory=dict)
    notes: str = ""

    # ----- persistence --------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": PROFILE_VERSION,
            "name": self.name,
            "mac": self.mac,
            "ip_hint": self.ip_hint,
            "device_port": self.device_port,
            "interaction": self.interaction,
            "source": self.source,
            "modbus": self.modbus,
            "registers": [r.to_dict() for r in self.registers],
            "request_framing": self.request_framing.to_dict(),
            "response_framing": (
                self.response_framing.to_dict() if self.response_framing else None
            ),
            "signals": [s.to_dict() for s in self.signals],
            "session": self.session,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceProfile":
        version = d.get("version", PROFILE_VERSION)
        if version > PROFILE_VERSION:
            raise ValueError(
                f"profile was written by a newer version of the app "
                f"(v{version} > v{PROFILE_VERSION})"
            )
        response = d.get("response_framing")
        return cls(
            name=d["name"],
            device_port=int(d["device_port"]),
            request_framing=FramingSpec.from_dict(d["request_framing"]),
            signals=[SignalSpec.from_dict(s) for s in d.get("signals", [])],
            interaction=d.get("interaction", "request_response"),
            source=d.get("source", SOURCE_SNIFF),
            modbus=d.get("modbus") or {},
            registers=[
                RegisterSpec.from_dict(r) for r in (d.get("registers") or [])
            ],
            response_framing=FramingSpec.from_dict(response) if response else None,
            mac=d.get("mac", ""),
            ip_hint=d.get("ip_hint", ""),
            session=d.get("session", {}),
            notes=d.get("notes", ""),
        )

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "DeviceProfile":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # ----- lookup -------------------------------------------------------

    def validate(self) -> List[str]:
        """Return every problem found, as sentences a person can act on.

        Profiles can arrive from outside the app — hand-edited, or written by
        something analysing a survey export — so they cannot be assumed
        well-formed. Most mistakes here decode to plausible-looking numbers
        rather than raising, so an unchecked profile produces a CSV full of
        wrong values that looks entirely normal. Every problem is collected
        rather than raising on the first, since fixing them one round-trip at a
        time is miserable.
        """
        from .fields import ENCODINGS

        known = {name for name, _dt, _size, _f in ENCODINGS}
        problems: List[str] = []

        if not self.name.strip():
            problems.append("The profile needs a name.")
        if not 0 <= self.device_port <= 65535:
            problems.append(
                f"device_port is {self.device_port}; it must be between 0 and 65535."
            )
        if self.interaction not in ("request_response", "server_push"):
            problems.append(
                f"interaction is {self.interaction!r}; expected "
                "'request_response' or 'server_push'."
            )
        if self.source not in (SOURCE_SNIFF, SOURCE_MODBUS):
            problems.append(
                f"source is {self.source!r}; expected "
                f"'{SOURCE_SNIFF}' or '{SOURCE_MODBUS}'."
            )

        if self.is_modbus:
            problems.extend(self._validate_modbus())
            return problems

        if not self.signals:
            problems.append("The profile defines no signals, so it would record nothing.")

        seen: Dict[str, int] = {}
        for i, signal in enumerate(self.signals):
            where = f"signal {i + 1}"
            if signal.name.strip():
                where = f"signal {i + 1} ({signal.name})"
            else:
                problems.append(f"{where} has no name; the name becomes a CSV column.")

            seen[signal.name] = seen.get(signal.name, 0) + 1

            if signal.encoding.startswith("ascii#"):
                index = signal.encoding.split("#", 1)[1]
                if not index.isdigit():
                    problems.append(
                        f"{where}: encoding {signal.encoding!r} should be "
                        "'ascii#N' where N is which number in the reply to take."
                    )
            elif signal.encoding not in known:
                problems.append(
                    f"{where}: encoding {signal.encoding!r} is not one of "
                    + ", ".join(sorted(known))
                    + ", or ascii#N."
                )

            if signal.offset < 0:
                problems.append(f"{where}: offset {signal.offset} cannot be negative.")

            if signal.mask and len(signal.mask) != len(signal.signature):
                problems.append(
                    f"{where}: mask has {len(signal.mask)} entries but the "
                    f"request is {len(signal.signature)} bytes; they must match "
                    "one-to-one."
                )

            if self.interaction == "request_response" and not signal.signature:
                problems.append(
                    f"{where}: no request signature. A request/response device "
                    "needs to know which request this signal answers — copy it "
                    "from the channel's request_hex."
                )
            if self.interaction == "server_push" and signal.signature:
                problems.append(
                    f"{where}: has a request signature, but this profile is "
                    "marked 'server_push', where readings arrive unprompted. "
                    "Leave the signature empty or switch to 'request_response'."
                )

            if signal.scale == 0:
                problems.append(
                    f"{where}: scale is 0, which would record every reading as "
                    f"{signal.bias}."
                )

        for name, count in seen.items():
            if count > 1 and name.strip():
                problems.append(
                    f"The name {name!r} is used {count} times; each signal needs "
                    "its own CSV column."
                )

        if self.interaction == "server_push" and self.response_framing is None:
            problems.append(
                "A 'server_push' profile needs 'response_framing', since there "
                "are no requests to delimit the replies."
            )

        return problems

    def _validate_modbus(self) -> List[str]:
        """Check a device that is read rather than watched."""
        problems: List[str] = []
        if not self.registers:
            problems.append(
                "This profile reads Modbus registers but lists none, so it "
                "would record nothing."
            )
        framing = (self.modbus or {}).get("framing", "rtu_tcp")
        if framing not in ("rtu_tcp", "tcp"):
            problems.append(
                f"modbus.framing is {framing!r}; expected 'rtu_tcp' (what "
                "Questor5 calls RTU-TCP) or 'tcp' (standard Modbus TCP)."
            )
        unit = (self.modbus or {}).get("unit", 1)
        if not isinstance(unit, int) or not 0 <= unit <= 247:
            problems.append(f"modbus.unit is {unit!r}; expected 0 to 247.")

        seen: Dict[str, int] = {}
        for i, register in enumerate(self.registers):
            where = f"register {i + 1} ({register.name})" if register.name else f"register {i + 1}"
            if not register.name.strip():
                problems.append(f"{where} has no name; the name becomes a CSV column.")
            seen[register.name] = seen.get(register.name, 0) + 1
            if register.format not in MODBUS_FORMATS:
                problems.append(
                    f"{where}: format {register.format!r} is not one of "
                    + ", ".join(sorted(MODBUS_FORMATS))
                    + "."
                )
            if not 0 <= register.address <= 65535 * 2:
                problems.append(f"{where}: address {register.address} is out of range.")
            if register.scale == 0:
                problems.append(
                    f"{where}: scale is 0, which would record every reading as "
                    f"{register.bias}."
                )
            if register.format == "single" and register.scale_lo == register.scale_hi:
                problems.append(
                    f"{where}: scale_lo and scale_hi are equal, so every reading "
                    "would decode to the same number. These must match the "
                    "limits set in the vendor software exactly."
                )
        for name, count in seen.items():
            if count > 1 and name.strip():
                problems.append(
                    f"The name {name!r} is used {count} times; each register "
                    "needs its own CSV column."
                )
        return problems

    def signals_for(self, request: bytes) -> List[SignalSpec]:
        return [s for s in self.signals if s.matches(request)]

    @property
    def is_modbus(self) -> bool:
        return self.source == SOURCE_MODBUS

    @property
    def signal_names(self) -> List[str]:
        if self.is_modbus:
            return [r.name for r in self.registers]
        return [s.name for s in self.signals]

    @property
    def signal_units(self) -> Dict[str, str]:
        if self.is_modbus:
            return {r.name: r.unit for r in self.registers}
        return {s.name: s.unit for s in self.signals}


def bundled_profile_dir() -> Path:
    """Where the profiles shipped with the app live. Read-only.

    In an installed build this sits under Program Files (or inside the .app),
    so nothing may be written here: it needs administrator rights, and the
    installer replaces the whole directory on every update.
    """
    import sys

    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        return Path(frozen) / "profiles"
    return Path(__file__).resolve().parents[2] / "profiles"


def user_profile_dir() -> Path:
    """Where profiles the user creates or imports are kept.

    Deliberately outside the installation. Writing profiles next to the
    executable loses every one of them at the next update, which is the worst
    possible moment: the profile is what turns the app from a packet viewer
    into an instrument recorder, and re-deriving one means repeating an
    experiment.
    """
    import os
    import sys

    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home())
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "LAN Signal Sniffer" / "profiles"


def load_profiles(directory: Optional[Path] = None) -> List[DeviceProfile]:
    """Load the shipped profiles and the user's own.

    A user profile with the same name as a shipped one replaces it, so a
    corrected profile survives an update that would otherwise reinstate the
    original.
    """
    if directory is not None:
        directories = [Path(directory)]
    else:
        directories = [bundled_profile_dir(), user_profile_dir()]

    by_name: Dict[str, DeviceProfile] = {}
    for folder in directories:
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.json")):
            try:
                profile = DeviceProfile.load(path)
            except (ValueError, KeyError, json.JSONDecodeError, OSError):
                continue
            by_name[profile.name] = profile
    return [by_name[name] for name in sorted(by_name)]


# ----- live decoding --------------------------------------------------------


@dataclass
class Sample:
    """One decoded reading set, ready for the plot and the CSV."""

    ts: float
    values: Dict[str, float]


class LiveDecoder:
    """Applies a profile to chunks as they arrive, emitting decoded samples.

    A reply is everything the device sent between one request and the next, so a
    sample can only be completed once the following request appears. Recording
    therefore lags real time by exactly one poll interval; `flush` closes out the
    last pending sample when traffic stops.
    """

    def __init__(self, profile: DeviceProfile) -> None:
        self._profile = profile
        self._pending_request: Optional[bytes] = None
        self._pending_ts: float = 0.0
        self._response = bytearray()
        self._carry = bytearray()  # request bytes split across segments
        # When each request last got an answer, so a batch of records can be
        # spread across the interval it actually covers.
        self._last_reply: Dict[bytes, float] = {}

    @property
    def _is_push(self) -> bool:
        return self._profile.interaction == "server_push"

    def feed(self, chunks: Iterable[StreamChunk]) -> List[Sample]:
        if self._is_push:
            return self._feed_push(chunks)

        samples: List[Sample] = []
        for chunk in chunks:
            if chunk.direction == S2C:
                if self._pending_request is not None:
                    self._response.extend(chunk.data)
                continue

            if chunk.gap_before:
                # Bytes were lost, so the carried partial frame can no longer be
                # trusted to start on a boundary.
                self._carry.clear()

            for frame in self._frames_in(chunk):
                samples.extend(self._close_pending())
                self._pending_request = frame
                self._pending_ts = chunk.ts
                self._response.clear()
        return samples

    def _feed_push(self, chunks: Iterable[StreamChunk]) -> List[Sample]:
        """Decode a device that streams without being asked.

        There is no request to pair against, so each frame of the reply stream
        is a sample in its own right, and the signals are the ones recorded
        against an empty signature.
        """
        spec = self._profile.response_framing or self._profile.request_framing
        samples: List[Sample] = []
        for chunk in chunks:
            if chunk.direction != S2C:
                continue
            if chunk.gap_before:
                self._carry.clear()
            self._carry.extend(chunk.data)
            stream = TimedStream()
            stream.append(
                StreamChunk(
                    ts=chunk.ts,
                    flow=chunk.flow,
                    direction=S2C,
                    data=bytes(self._carry),
                    stream_offset=0,
                )
            )
            frames = split_frames(stream, spec)
            consumed = 0
            for frame in frames:
                consumed += len(frame.data)
                values = self._decode(frame.data, b"")
                if values:
                    samples.append(Sample(ts=chunk.ts, values=values))
            del self._carry[:consumed]
        return samples

    def flush(self) -> List[Sample]:
        """Complete the outstanding reply, if any, and clear state.

        A list, because the last reply of a session can carry a whole batch of
        readings and returning only the newest would drop the rest at exactly
        the moment there is no next poll to recover them.
        """
        if self._is_push:
            self._carry.clear()
            return []
        samples = self._close_pending()
        self._pending_request = None
        self._response.clear()
        self._carry.clear()
        return samples

    # ----- internals ----------------------------------------------------

    def _frames_in(self, chunk: StreamChunk) -> List[bytes]:
        """Split a client segment into whole request frames.

        A segment usually holds exactly one request, but a frame can straddle a
        segment boundary, so any trailing partial frame is carried forward.
        """
        self._carry.extend(chunk.data)
        stream = TimedStream()
        stream.append(
            StreamChunk(
                ts=chunk.ts,
                flow=chunk.flow,
                direction=C2S,
                data=bytes(self._carry),
                stream_offset=0,
            )
        )
        frames = split_frames(stream, self._profile.request_framing)
        consumed = sum(len(f.data) for f in frames)
        del self._carry[:consumed]
        return [f.data for f in frames]

    def _decode(self, payload: bytes, request: bytes) -> List[Dict[str, float]]:
        """Decode every reading this reply carries, oldest first.

        Usually one. An instrument that logs faster than it is polled answers
        with all the readings taken since the last request, packed back to back,
        and a signal marked with a stride says how far apart they sit.
        """
        specs = list(self._profile.signals_for(request))
        if not specs:
            return []
        records = max((spec.record_count(len(payload)) for spec in specs), default=1)
        out: List[Dict[str, float]] = []
        for index in range(max(records, 1)):
            values: Dict[str, float] = {}
            for spec in specs:
                if index and index >= spec.record_count(len(payload)):
                    # A signal without a stride has one reading per reply; it
                    # belongs to the first record and must not be repeated into
                    # the rest, which would invent samples it never reported.
                    continue
                offset = spec.offset + index * spec.stride
                raw = decode_field([payload], offset, spec.encoding)[0]
                if raw == raw:  # not NaN
                    values[spec.name] = spec.convert(float(raw))
            if values:
                out.append(values)
        return out

    def _close_pending(self) -> List[Sample]:
        """Finish the outstanding reply, as one sample or as many.

        Batched records are spread across the interval since this channel last
        answered, ending at the reply itself. The instrument stamps each record
        with its own time, but only to the second within the minute, so the
        capture clock plus even spacing is both simpler and no less accurate
        than reconstructing an absolute time from a partial one.
        """
        if self._pending_request is None or not self._response:
            return []
        payload = bytes(self._response)
        request = self._pending_request
        rows = self._decode(payload, request)
        self._response.clear()
        if not rows:
            return []

        end = self._pending_ts
        previous = self._last_reply.get(request)
        self._last_reply[request] = end
        if len(rows) == 1:
            return [Sample(ts=end, values=rows[0])]
        if previous is None or end <= previous:
            # The first batch on a channel has nothing to measure the interval
            # against, so only its newest reading has a time that is actually
            # known. Stacking the rest on that same instant would put readings
            # at times they were not taken, which is worse than not having
            # them; it costs under a second, once per channel per session.
            return [Sample(ts=end, values=rows[-1])]
        step = (end - previous) / len(rows)
        return [
            Sample(ts=end - (len(rows) - 1 - i) * step, values=row)
            for i, row in enumerate(rows)
        ]


def build_profile(
    name: str,
    device_port: int,
    request_framing: FramingSpec,
    chosen: Sequence[Tuple[str, str, bytes, List[bool], int, str, float, float]],
    **kwargs,
) -> DeviceProfile:
    """Assemble a profile from the wizard's selections.

    Each entry of `chosen` is (name, unit, signature, mask, offset, encoding,
    scale, bias) — the row the user filled in for one signal.
    """
    signals = [
        SignalSpec(
            name=n,
            unit=u,
            signature=sig,
            mask=list(mask),
            offset=off,
            encoding=enc,
            scale=scale,
            bias=bias,
        )
        for n, u, sig, mask, off, enc, scale, bias in chosen
    ]
    return DeviceProfile(
        name=name,
        device_port=device_port,
        request_framing=request_framing,
        signals=signals,
        **kwargs,
    )
