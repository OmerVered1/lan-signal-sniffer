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
from .fields import decode_field
from .framer import FramingSpec, TimedStream, apply_mask, split_frames

PROFILE_VERSION = 1


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
        }

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
        )


@dataclass
class DeviceProfile:
    """Everything needed to turn one device's traffic back into measurements."""

    name: str
    device_port: int
    request_framing: FramingSpec
    signals: List[SignalSpec] = field(default_factory=list)
    interaction: str = "request_response"
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

    def signals_for(self, request: bytes) -> List[SignalSpec]:
        return [s for s in self.signals if s.matches(request)]

    @property
    def signal_names(self) -> List[str]:
        return [s.name for s in self.signals]


def load_profiles(directory: Path) -> List[DeviceProfile]:
    """Load every profile in a directory, skipping ones that fail to parse."""
    out: List[DeviceProfile] = []
    directory = Path(directory)
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(DeviceProfile.load(path))
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return out


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
                done = self._close_pending()
                if done is not None:
                    samples.append(done)
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

    def flush(self) -> Optional[Sample]:
        """Complete the outstanding sample, if any, and clear state."""
        if self._is_push:
            self._carry.clear()
            return None
        sample = self._close_pending()
        self._pending_request = None
        self._response.clear()
        self._carry.clear()
        return sample

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

    def _decode(self, payload: bytes, request: bytes) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for spec in self._profile.signals_for(request):
            raw = decode_field([payload], spec.offset, spec.encoding)[0]
            if raw == raw:  # not NaN
                values[spec.name] = spec.convert(float(raw))
        return values

    def _close_pending(self) -> Optional[Sample]:
        if self._pending_request is None or not self._response:
            return None
        values = self._decode(bytes(self._response), self._pending_request)
        self._response.clear()
        if not values:
            return None
        return Sample(ts=self._pending_ts, values=values)


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
