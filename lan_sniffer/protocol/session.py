# READ-ONLY MODULE
"""Decide when the vendor software has started and stopped an experiment.

Whether this can be detected at all depends on the device, and it cannot be
known in advance: some vendor software polls only during a run, and some polls
continuously from the moment it connects. Guessing wrong either misses runs or
splits files at random.

So the app does not guess. It asks the user to capture a couple of minutes with
the instrument idle and a couple with a run in progress, and compares them. That
comparison picks one of three strategies, in descending order of reliability:

    signature  a run sends requests that idle never sends — unambiguous
    cadence    the same requests, but markedly faster during a run
    manual     nothing separates them, which the app says plainly rather than
               shipping a detector that fires at random

A manual Start / Stop / Split is available in every mode, so a device that
cannot be detected is inconvenient rather than unusable.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

# A run has to look different by this much before cadence is believed.
MIN_RATE_RATIO = 1.5
# Positive observations within one quiet window before a session opens, and
# quiet seconds before it closes. Both guard against a stray packet opening or
# cutting a file. Counted within a window rather than consecutively, because the
# trigger request is one step of a polling rotation and is always interleaved
# with the others.
DEFAULT_START_STREAK = 3
DEFAULT_QUIET_SECONDS = 30.0

MODE_SIGNATURE = "signature"
MODE_CADENCE = "cadence"
MODE_MANUAL = "manual"


@dataclass
class Calibration:
    """What comparing an idle capture with a running one revealed.

    `request_mask` records which byte positions were treated as identifying,
    keyed by request length. It has to be stored rather than recomputed: if a
    protocol carries a transaction counter, every request is literally unique,
    and comparing raw bytes would make every single one look like a request that
    only ever appears during a run.
    """

    mode: str
    trigger_signatures: List[str] = field(default_factory=list)
    # Explicit end-of-run commands. Without these a session can only close on a
    # quiet timeout, which never arrives on an instrument whose software polls
    # continuously between runs — the session would open and stay open for ever.
    stop_signatures: List[str] = field(default_factory=list)
    rate_threshold: float = 0.0
    idle_rate: float = 0.0
    running_rate: float = 0.0
    start_streak: int = DEFAULT_START_STREAK
    quiet_seconds: float = DEFAULT_QUIET_SECONDS
    request_mask: Dict[int, List[bool]] = field(default_factory=dict)
    explanation: str = ""

    @property
    def automatic(self) -> bool:
        return self.mode != MODE_MANUAL

    def signature_of(self, request: bytes) -> str:
        """Reduce a request to the identity the detector compares against."""
        mask = self.request_mask.get(len(request))
        if not mask:
            return request.hex()
        return bytes(b if keep else 0 for b, keep in zip(request, mask)).hex()

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "trigger_signatures": list(self.trigger_signatures),
            "stop_signatures": list(self.stop_signatures),
            "rate_threshold": self.rate_threshold,
            "idle_rate": self.idle_rate,
            "running_rate": self.running_rate,
            "start_streak": self.start_streak,
            "quiet_seconds": self.quiet_seconds,
            # JSON object keys must be strings.
            "request_mask": {
                str(k): [bool(b) for b in v] for k, v in self.request_mask.items()
            },
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Calibration":
        return cls(
            mode=d.get("mode", MODE_MANUAL),
            trigger_signatures=list(d.get("trigger_signatures", [])),
            stop_signatures=list(d.get("stop_signatures", [])),
            rate_threshold=float(d.get("rate_threshold", 0.0)),
            idle_rate=float(d.get("idle_rate", 0.0)),
            running_rate=float(d.get("running_rate", 0.0)),
            start_streak=int(d.get("start_streak", DEFAULT_START_STREAK)),
            quiet_seconds=float(d.get("quiet_seconds", DEFAULT_QUIET_SECONDS)),
            request_mask={
                int(k): [bool(b) for b in v]
                for k, v in (d.get("request_mask") or {}).items()
            },
            explanation=d.get("explanation", ""),
        )


@dataclass
class Observation:
    """One request seen on the wire, reduced to what the detector needs."""

    ts: float
    signature: str


def _rate(events: Sequence[Observation]) -> float:
    """Requests per second across a capture."""
    if len(events) < 2:
        return 0.0
    span = events[-1].ts - events[0].ts
    return (len(events) - 1) / span if span > 0 else 0.0


def calibrate_from_requests(
    idle: Sequence[Tuple[float, bytes]],
    running: Sequence[Tuple[float, bytes]],
) -> Calibration:
    """Calibrate from raw request frames, working out the mask first.

    The mask is derived from both legs together. Deriving it from one leg alone
    would let a counter's observed range differ between them and change which
    positions count as identity.
    """
    from .framer import signature_mask

    combined: Dict[int, List[bytes]] = {}
    for _ts, request in list(idle) + list(running):
        combined.setdefault(len(request), []).append(request)
    masks = {length: signature_mask(reqs) for length, reqs in combined.items()}

    def to_obs(items: Sequence[Tuple[float, bytes]]) -> List[Observation]:
        out = []
        for ts, request in items:
            mask = masks.get(len(request))
            sig = (
                bytes(b if k else 0 for b, k in zip(request, mask)).hex()
                if mask
                else request.hex()
            )
            out.append(Observation(ts=ts, signature=sig))
        return out

    calibration = calibrate(to_obs(idle), to_obs(running))
    calibration.request_mask = masks
    return calibration


def calibrate(
    idle: Sequence[Observation], running: Sequence[Observation]
) -> Calibration:
    """Compare an idle capture with a running one and choose a strategy."""
    idle_sigs = {o.signature for o in idle}
    run_sigs = {o.signature for o in running}
    idle_rate = _rate(idle)
    running_rate = _rate(running)

    if not running:
        return Calibration(
            mode=MODE_MANUAL,
            idle_rate=idle_rate,
            explanation=(
                "No traffic at all was seen during the running capture. Check "
                "that the capture was armed and that the right device was "
                "selected, then calibrate again."
            ),
        )

    exclusive = sorted(run_sigs - idle_sigs)
    if exclusive:
        shown = ", ".join(exclusive[:3]) + ("…" if len(exclusive) > 3 else "")
        note = (
            f"A run sends {len(exclusive)} request(s) that never appear while "
            f"idle ({shown}). Seeing one of those starts a session."
        )
        if not idle:
            # Every running request looks exclusive when nothing was recorded to
            # compare against. The resulting detector is sound for a device that
            # really is silent when idle, and wrong if the idle capture simply
            # missed the traffic — which the user is the only one able to tell.
            note = (
                "No traffic at all was seen while idle, so any request is "
                "treated as the start of a run. That is correct if the "
                "instrument is genuinely silent between experiments — if it "
                "was not actually connected during the idle capture, record "
                "that leg again."
            )
        return Calibration(
            mode=MODE_SIGNATURE,
            trigger_signatures=exclusive,
            idle_rate=idle_rate,
            running_rate=running_rate,
            explanation=note,
        )

    if idle_rate == 0.0 and running_rate > 0.0:
        return Calibration(
            mode=MODE_CADENCE,
            rate_threshold=running_rate / 2.0,
            idle_rate=idle_rate,
            running_rate=running_rate,
            explanation=(
                "The device is silent while idle and polled at "
                f"{running_rate:.2f} requests/s during a run, so any sustained "
                "polling means a run has started."
            ),
        )

    if running_rate >= idle_rate * MIN_RATE_RATIO and idle_rate > 0.0:
        threshold = math.sqrt(idle_rate * running_rate)
        return Calibration(
            mode=MODE_CADENCE,
            rate_threshold=threshold,
            idle_rate=idle_rate,
            running_rate=running_rate,
            explanation=(
                f"The same requests are sent either way, but polling speeds up "
                f"from {idle_rate:.2f} to {running_rate:.2f} requests/s during a "
                f"run. Crossing {threshold:.2f} requests/s starts a session."
            ),
        )

    return Calibration(
        mode=MODE_MANUAL,
        idle_rate=idle_rate,
        running_rate=running_rate,
        explanation=(
            "Idle and running traffic look the same: the same requests at "
            f"{idle_rate:.2f} and {running_rate:.2f} requests/s. Nothing on the "
            "wire distinguishes them, so sessions have to be started and "
            "stopped by hand. Recording still works; only the automation does "
            "not."
        ),
    )


class SessionDetector:
    """Turns a stream of observations into session start and stop events.

    Feed it every request with `observe`, and call `tick` periodically so a
    session can end when traffic simply stops. `start`, `stop` and `split` are
    the manual controls, and they work in every mode.
    """

    def __init__(self, calibration: Calibration, window_seconds: float = 20.0) -> None:
        self._cal = calibration
        self._window = window_seconds
        self._recent: Deque[float] = deque()
        self._positives: Deque[float] = deque()
        self._running = False
        self._last_positive: Optional[float] = None
        # Set when the running session was started by hand. It suppresses the
        # quiet timeout for that session only — it must never disable
        # detection itself, which is what a sticky override did: one press of
        # Stop, or one capture restart, and no run was ever auto-detected
        # again for the life of the process.
        self._hand_started = False

        # Diagnostics. When a session fails to start there is nothing on screen
        # to say why, and the two likely causes — the capture began after the
        # run did, or the instrument sent a variant of the expected command —
        # look identical from the outside. These make them distinguishable.
        self.observed = 0
        self.last_trigger_ts: Optional[float] = None
        self.last_stop_ts: Optional[float] = None
        self.near_misses: Deque[str] = deque(maxlen=8)

    @property
    def trigger_prefixes(self) -> List[str]:
        """Command families the triggers belong to.

        A near miss is a request from the same family as a trigger but with a
        different value — exactly what a differing firmware or a second control
        register would produce, and worth showing rather than discarding.
        """
        prefixes = set()
        for sig in list(self._cal.trigger_signatures) + list(self._cal.stop_signatures):
            if len(sig) > 4:
                prefixes.add(sig[:-2])
        return sorted(prefixes)

    def _note(self, obs: Observation) -> None:
        self.observed += 1
        if obs.signature in self._cal.trigger_signatures:
            self.last_trigger_ts = obs.ts
            return
        if obs.signature in self._cal.stop_signatures:
            self.last_stop_ts = obs.ts
            return
        for prefix in self.trigger_prefixes:
            if obs.signature.startswith(prefix) and obs.signature not in self.near_misses:
                self.near_misses.append(obs.signature)
                break

    @property
    def running(self) -> bool:
        return self._running

    @property
    def calibration(self) -> Calibration:
        return self._cal

    def observe(self, obs: Observation) -> Optional[str]:
        """Report one request. Returns "start", "stop", or None."""
        self._note(obs)
        self._recent.append(obs.ts)
        while self._recent and obs.ts - self._recent[0] > self._window:
            self._recent.popleft()

        if self._cal.mode == MODE_MANUAL:
            if self._running:
                self._last_positive = obs.ts
            return None

        # An explicit end-of-run command is unambiguous, so it closes the
        # session at once rather than waiting for traffic to fall quiet.
        if self._running and obs.signature in self._cal.stop_signatures:
            self._running = False
            self._positives.clear()
            return "stop"

        if not self._is_positive(obs):
            # Deliberately not a reset. The trigger request is one step of a
            # polling rotation, so it is always separated by the other requests
            # in the cycle — demanding consecutive hits would mean a session
            # could never start at all. Sustained absence ends a session through
            # the quiet timeout instead.
            return None

        self._last_positive = obs.ts
        self._positives.append(obs.ts)
        while self._positives and obs.ts - self._positives[0] > self._cal.quiet_seconds:
            self._positives.popleft()

        if not self._running and len(self._positives) >= self._cal.start_streak:
            self._running = True
            return "start"
        return None

    def tick(self, now: float) -> Optional[str]:
        """Check whether a running session has gone quiet long enough to end."""
        if not self._running or self._hand_started:
            return None
        if self._last_positive is None:
            return None
        if self._cal.stop_signatures:
            # The run ends on a command, not on silence. Timing out here would
            # cut the file mid-experiment during any lull in the trigger.
            return None
        if now - self._last_positive >= self._cal.quiet_seconds:
            self._running = False
            self._positives.clear()
            return "stop"
        return None

    # ----- manual controls ----------------------------------------------

    def start(self, now: float) -> None:
        """Begin recording by hand.

        Automatic detection keeps running: an explicit stop command should
        still close a session the user opened, and the next run should still be
        picked up on its own.
        """
        self._running = True
        self._last_positive = now
        self._hand_started = True

    def stop(self) -> None:
        """End the current session by hand, and stay armed for the next run."""
        self._running = False
        self._positives.clear()
        self._hand_started = False

    def resume_automatic(self) -> None:
        """Drop the hand-started marker, restoring the quiet timeout."""
        self._hand_started = False
        self._positives.clear()

    # ----- internals ----------------------------------------------------

    def _is_positive(self, obs: Observation) -> bool:
        if self._cal.mode == MODE_SIGNATURE:
            return obs.signature in self._cal.trigger_signatures
        if self._cal.mode == MODE_CADENCE:
            span = self._recent[-1] - self._recent[0] if len(self._recent) > 1 else 0.0
            rate = (len(self._recent) - 1) / span if span > 0 else 0.0
            return rate >= self._cal.rate_threshold
        return False
