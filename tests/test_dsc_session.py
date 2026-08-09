"""Explicit start/stop commands, and the shipped Setline DSC profile.

Everything here comes from a real capture taken on 2026-08-09 alongside
Calisto's own export of the same run, so the shapes are the instrument's rather
than ones invented to suit the code.

Two findings drove the behaviour under test. Calisto controls a run by writing a
value to one register — 0004 0001 0000 05 to start, 0004 0001 0000 02 to stop —
and it sends each exactly once. And it polls this instrument continuously
between runs, so silence never falls. A detector that needs several sightings
and ends sessions on a quiet timeout gets both halves wrong: it never starts,
and if it did it would never stop.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
import synth

from lan_sniffer.protocol.profile import DeviceProfile, LiveDecoder
from lan_sniffer.protocol.session import (
    MODE_SIGNATURE,
    Calibration,
    Observation,
    SessionDetector,
)

PROFILE_DIR = Path(__file__).resolve().parents[1] / "profiles"

START_CMD = "00040001000005"
STOP_CMD = "00040001000002"
IDLE_POLL = "000100020004"


def dsc_calibration() -> Calibration:
    return Calibration(
        mode=MODE_SIGNATURE,
        trigger_signatures=[START_CMD],
        stop_signatures=[STOP_CMD],
        start_streak=1,
        quiet_seconds=120.0,
    )


# ----- one-shot start and stop ----------------------------------------------


def test_a_single_start_command_opens_a_session():
    # The command is sent once. Requiring a streak would mean it never fires.
    det = SessionDetector(dsc_calibration())
    assert det.observe(Observation(20.0, START_CMD)) == "start"
    assert det.running


def test_an_explicit_stop_command_closes_the_session():
    det = SessionDetector(dsc_calibration())
    det.observe(Observation(20.0, START_CMD))
    assert det.observe(Observation(920.0, STOP_CMD)) == "stop"
    assert not det.running


def test_continuous_idle_polling_never_ends_the_session():
    """The failure this replaces: closing on silence that never comes.

    Calisto polls this instrument all the way through, so the quiet timeout
    would either never fire or, worse, fire during a lull and cut the file in
    the middle of a run.
    """
    det = SessionDetector(dsc_calibration())
    det.observe(Observation(20.0, START_CMD))
    for i in range(1, 900):
        det.observe(Observation(20.0 + i, IDLE_POLL))
    assert det.running, "the run is still going; only the stop command ends it"
    assert det.tick(20.0 + 100_000) is None, "no timeout when a stop command exists"
    assert det.running


def test_idle_polling_alone_never_opens_a_session():
    det = SessionDetector(dsc_calibration())
    for i in range(500):
        det.observe(Observation(float(i), IDLE_POLL))
    assert not det.running


def test_a_stop_before_any_start_is_ignored():
    det = SessionDetector(dsc_calibration())
    assert det.observe(Observation(5.0, STOP_CMD)) is None
    assert not det.running


def test_consecutive_runs_each_get_their_own_session():
    det = SessionDetector(dsc_calibration())
    events = []
    for ts, sig in [
        (20.0, START_CMD), (500.0, IDLE_POLL), (920.0, STOP_CMD),
        (1500.0, START_CMD), (2000.0, IDLE_POLL), (2400.0, STOP_CMD),
    ]:
        events.append(det.observe(Observation(ts, sig)))
    assert [e for e in events if e] == ["start", "stop", "start", "stop"]


def test_quiet_timeout_still_applies_when_there_is_no_stop_command():
    # Devices without an explicit stop command must keep the old behaviour.
    cal = Calibration(
        mode=MODE_SIGNATURE,
        trigger_signatures=["go"],
        start_streak=1,
        quiet_seconds=30.0,
    )
    det = SessionDetector(cal)
    det.observe(Observation(0.0, "go"))
    assert det.tick(31.0) == "stop"


def test_stop_signatures_survive_the_profile_round_trip(tmp_path):
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    profile.save(tmp_path / "copy.json")
    again = Calibration.from_dict(DeviceProfile.load(tmp_path / "copy.json").session)
    assert again.stop_signatures == [STOP_CMD]
    assert again.trigger_signatures == [START_CMD]


# ----- the shipped DSC profile ----------------------------------------------


def test_shipped_dsc_profile_is_valid():
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    assert profile.validate() == []
    assert profile.signal_names == ["sample_temperature", "heat_flow"]


def test_dsc_profile_reads_both_signals_from_the_packed_status_frame():
    """Both quantities live in one 23-byte reply to the 2-byte request 0008.

    Values here are the first sample of the real capture, which Calisto's export
    records as 25.629 degC and -0.61916 uV.
    """
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    reply = bytearray(bytes.fromhex("0008000100011b03000110370a0001") + b"\x00" * 8)
    struct.pack_into(">f", reply, 15, 25.629)
    struct.pack_into(">f", reply, 19, -0.61916)

    chunks = synth.build_capture(
        [(float(i), bytes.fromhex("0008"), i + 0.01, bytes(reply)) for i in range(12)],
    )
    samples = LiveDecoder(profile).feed(chunks)
    assert samples
    assert samples[0].values["sample_temperature"] == pytest.approx(25.629, abs=1e-4)
    assert samples[0].values["heat_flow"] == pytest.approx(-0.61916, abs=1e-5)


def test_dsc_profile_does_not_reuse_the_c80_commands():
    """A deliberate negative.

    This device answers the C80's own request bytes with values in a plausible
    range, which made it look as though the C80 profile would work. Correlated
    against Calisto they track at r=0.73 and r=0.50 — they are not the signals
    being plotted. The profile must not quietly depend on them.
    """
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    signatures = {s.signature.hex() for s in profile.signals}
    assert "000100080004" not in signatures
    assert "0001000a0001" not in signatures
    assert signatures == {"0008"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
