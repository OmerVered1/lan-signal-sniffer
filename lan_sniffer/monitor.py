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
        self.apply_profile(config.profile)

    # ----- configuration --------------------------------------------------

    def apply_profile(self, profile: Optional[DeviceProfile]) -> None:
        self.config.profile = profile
        self.decoder = LiveDecoder(profile) if profile else None
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
        return [self.qualify(s.name) for s in self.profile.signals]

    def units(self) -> Dict[str, str]:
        if not self.profile:
            return {}
        return {self.qualify(s.name): s.unit for s in self.profile.signals}

    # ----- capture --------------------------------------------------------

    @property
    def capturing(self) -> bool:
        return self.pump is not None

    def start_capture(self, interface: Optional[str]) -> None:
        self.pump = PacketPump(self.config.ip, self.config.port or None, interface)
        self.pump.start()
        self.analysis_buffer.clear()
        self._carry.clear()

    def stop_capture(self) -> None:
        pump, self.pump = self.pump, None
        if pump is not None:
            pump.stop()

    def status(self) -> str:
        return self.pump.status() if self.pump else "not capturing"

    # ----- the loop -------------------------------------------------------

    def poll(self) -> PollResult:
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
