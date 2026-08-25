"""One device being watched: its capture, its decoding, its run detection.

Everything that used to be a single set of fields on the main window — pump,
profile, decoder, detector, buffers — belongs to a device, and a session can
now span several. Keeping it here rather than in the window has a second
purpose: this class has no Qt in it, so the whole capture-to-sample path can be
driven from a test. The bugs that reached the bench all lived in seams between
components that were individually tested and never driven together.

Signal names are qualified with a device prefix only when more than one device
is configured. A single-device recording therefore produces exactly the columns
it always did, and files from before this existed stay comparable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from .capture.capture import PacketPump
from .capture.reassembly import C2S, StreamChunk
from .protocol.framer import TimedStream, split_frames
from .protocol.profile import DeviceProfile, LiveDecoder, Sample
from .readers.modbus import ModbusClient, ModbusError
from .protocol.session import Calibration, Observation, SessionDetector

# Chunks retained per device for identification. Enough for a few hundred poll
# cycles, well past what the scan needs.
ANALYSIS_BUFFER = 20000


@dataclass
class DeviceConfig:
    """What the user chose for one device."""

    label: str = ""
    ip: str = ""
    port: Optional[int] = 1210
    interface: Optional[str] = None
    profile: Optional[DeviceProfile] = None
    # Whether this device's experiment drives the recording. In a coupled
    # setup one instrument runs the experiment and the others are along for
    # the ride: a TPD rig is an oven under Calisto with a mass spectrometer
    # watching the evolved gas, and the run is the oven's. The gas analyser
    # polls continuously and has no notion of a run at all, so letting it open
    # or close the file would be wrong.
    controls_recording: bool = True


@dataclass
class PollResult:
    """What one device produced since the last poll."""

    chunks: List[StreamChunk] = field(default_factory=list)
    samples: List[Sample] = field(default_factory=list)
    events: List[Tuple[str, float]] = field(default_factory=list)


class DeviceMonitor:
    """Capture, decode and run-detection for a single device."""

    def __init__(self, config: DeviceConfig) -> None:
        self.config = config
        self.pump: Optional[PacketPump] = None
        self.decoder: Optional[LiveDecoder] = None
        self.detector: Optional[SessionDetector] = None
        self.analysis_buffer: List[StreamChunk] = []
        self.request_sink: Optional[List[Tuple[float, bytes]]] = None
        # Whether this device's own experiment is currently running. A session
        # may cover several devices, so the file's state and a device's state
        # are not the same thing.
        self.running = False
        self.prefix = ""
        self._carry = bytearray()
        # Only set for a device that is read rather than sniffed.
        self.reader: Optional[ModbusClient] = None
        self._next_read = 0.0
        self.last_error: Optional[str] = None
        self.apply_profile(config.profile)

    # ----- configuration --------------------------------------------------

    @property
    def reads_registers(self) -> bool:
        """True for a device that is asked for its values rather than watched."""
        return bool(self.profile and self.profile.is_modbus)

    def apply_profile(self, profile: Optional[DeviceProfile]) -> None:
        self.config.profile = profile
        self.close_reader()
        self.decoder = LiveDecoder(profile) if profile and not profile.is_modbus else None
        self.detector = (
            SessionDetector(Calibration.from_dict(profile.session or {}))
            if profile
            else None
        )
        self.running = False

    @property
    def profile(self) -> Optional[DeviceProfile]:
        return self.config.profile

    @property
    def name(self) -> str:
        return self.config.label or self.config.ip or "device"

    def qualify(self, signal: str) -> str:
        return f"{self.prefix}{signal}" if self.prefix else signal

    def signal_names(self) -> List[str]:
        if not self.profile:
            return []
        return [self.qualify(name) for name in self.profile.signal_names]

    def units(self) -> Dict[str, str]:
        if not self.profile:
            return {}
        return {
            self.qualify(name): unit
            for name, unit in self.profile.signal_units.items()
        }

    # ----- capture --------------------------------------------------------

    @property
    def capturing(self) -> bool:
        return self.pump is not None

    def start_capture(self, interface: Optional[str]) -> None:
        if self.reads_registers:
            self.open_reader()
            return
        self.pump = PacketPump(self.config.ip, self.config.port or None, interface)
        self.pump.start()
        self.analysis_buffer.clear()
        self._carry.clear()

    def stop_capture(self) -> None:
        self.close_reader()
        pump, self.pump = self.pump, None
        if pump is not None:
            pump.stop()

    def open_reader(self) -> None:
        """Connect to the instrument's Modbus slave.

        This is the one place the app opens a connection to an instrument. A
        Modbus slave exists to be polled and normally accepts several masters,
        so this does not take anything away from the vendor software the way
        connecting to a single-client instrument would.
        """
        settings = (self.profile.modbus if self.profile else None) or {}
        self.reader = ModbusClient(
            self.config.ip,
            self.config.port or 502,
            unit=int(settings.get("unit", 1)),
            framing=str(settings.get("framing", "rtu_tcp")),
            timeout=float(settings.get("timeout_s", 3.0)),
        )
        self._next_read = 0.0
        self.last_error = None

    def close_reader(self) -> None:
        reader, self.reader = getattr(self, "reader", None), None
        if reader is not None:
            reader.close()

    def status(self) -> str:
        if self.reads_registers:
            if self.last_error:
                return f"read failed: {self.last_error}"
            return "reading registers" if self.reader else "not reading"
        return self.pump.status() if self.pump else "not capturing"

    # ----- the loop -------------------------------------------------------

    def poll(self) -> PollResult:
        """Produce whatever this device has to offer since the last call."""
        if self.reads_registers:
            return self._poll_registers()
        return self._poll_capture()

    def _poll_registers(self) -> PollResult:
        """Ask the slave for its registers, no faster than configured.

        A failed read is reported and retried rather than raised: an analyser
        restarting mid-run should interrupt its own columns, not the recording
        of the instrument that is driving the experiment.
        """
        import time as _time

        result = PollResult()
        if self.reader is None or not self.profile:
            return result
        now = _time.time()
        if now < self._next_read:
            return result
        interval = float((self.profile.modbus or {}).get("poll_interval_s", 2.0))
        self._next_read = now + max(0.2, interval)

        try:
            values = self.reader.read(self.profile.registers)
            self.last_error = None
        except (ModbusError, OSError) as e:
            self.last_error = str(e)
            self.reader.close()
            return result
        if values:
            result.samples.append(
                Sample(ts=now, values={self.qualify(k): v for k, v in values.items()})
            )
        return result

    def _poll_capture(self) -> PollResult:
        """Drain captured packets into decoded samples and session events."""
        result = PollResult()
        if self.pump is None:
            return result

        result.chunks = self.pump.poll()
        if not result.chunks:
            return result

        self.analysis_buffer.extend(result.chunks)
        del self.analysis_buffer[:-ANALYSIS_BUFFER]

        for ts, frame in self.iter_requests(result.chunks):
            if self.request_sink is not None:
                self.request_sink.append((ts, frame))
            if self.detector is not None:
                signature = self.detector.calibration.signature_of(frame)
                event = self.detector.observe(Observation(ts, signature))
                if event:
                    result.events.append((event, ts))

        if self.decoder is not None:
            for sample in self.decoder.feed(result.chunks):
                result.samples.append(
                    Sample(
                        ts=sample.ts,
                        values={self.qualify(k): v for k, v in sample.values.items()},
                    )
                )
        return result

    def tick(self, now: float) -> Optional[str]:
        """Let a quiet period close a run, for devices without a stop command."""
        return self.detector.tick(now) if self.detector is not None else None

    def flush(self) -> Optional[Sample]:
        """Complete the reply still in hand when a session ends."""
        if self.decoder is None:
            return None
        tail = self.decoder.flush()
        if tail is None:
            return None
        return Sample(
            ts=tail.ts, values={self.qualify(k): v for k, v in tail.values.items()}
        )

    def iter_requests(self, chunks: List[StreamChunk]) -> Iterator[Tuple[float, bytes]]:
        """Split client segments into whole request frames, carrying partials."""
        for chunk in chunks:
            if chunk.direction != C2S:
                continue
            if chunk.gap_before:
                self._carry.clear()
            self._carry.extend(chunk.data)

            if self.profile is None:
                # Without a profile the segment is the best frame guess there
                # is, which is the same fallback the framer uses.
                yield chunk.ts, bytes(self._carry)
                self._carry.clear()
                continue

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
            frames = split_frames(stream, self.profile.request_framing)
            consumed = 0
            for frame in frames:
                consumed += len(frame.data)
                yield chunk.ts, frame.data
            del self._carry[:consumed]
