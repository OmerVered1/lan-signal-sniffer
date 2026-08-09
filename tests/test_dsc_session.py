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
    # The two Calisto exports come first; the control-loop channels follow.
    assert profile.signal_names[:2] == ["sample_temperature", "heat_flow"]


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


def test_dsc_profile_records_the_control_loop_too():
    """Furnace, setpoint, error and power, not just the two Calisto exports.

    These were identified by the relation control_error + furnace ==
    programmed_setpoint, which holds to 0.045 degC over the real run. That is
    also what makes the furnace the furnace: the loop regulates it.
    """
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    assert set(profile.signal_names) == {
        "sample_temperature",
        "heat_flow",
        "furnace_temperature",
        "programmed_setpoint",
        "control_error",
        "heater_power",
        "heater_power_averaged",
    }
    by_name = {s.name: s for s in profile.signals}
    # The setpoint is the one f64 in the set; reading it as f32 gives nonsense.
    assert by_name["programmed_setpoint"].encoding == "f64be"
    assert by_name["heater_power"].unit == "%"
    assert by_name["furnace_temperature"].unit == "degC"


def test_control_loop_signals_decode_and_satisfy_the_identity():
    """Decode a synthetic reply set and check the algebra survives the profile.

    Guards the offsets and encodings: transpose two of them and the identity
    stops holding, which no range check on an individual signal would catch.
    """
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_dsc_setline.json")
    setpoint, furnace = 40.15, 38.11
    error = setpoint - furnace

    def reply_for(sig: bytes, value: float, fmt: str) -> bytes:
        body = bytearray(b"\x00" * (6 + (8 if fmt == ">d" else 4)))
        body[0 : len(sig)] = sig
        struct.pack_into(fmt, body, 6, value)
        return bytes(body)

    exchanges = []
    ts = 0.0
    for _ in range(12):
        for sig_hex, value, fmt in (
            ("000100020005", furnace, ">f"),
            ("000100100000", setpoint, ">d"),
            ("000100020006", error, ">f"),
        ):
            sig = bytes.fromhex(sig_hex)
            exchanges.append((ts, sig, ts + 0.01, reply_for(sig, value, fmt)))
            ts += 0.1

    samples = LiveDecoder(profile).feed(synth.build_capture(exchanges))
    seen = {}
    for s in samples:
        seen.update(s.values)
    assert seen["furnace_temperature"] == pytest.approx(furnace, abs=1e-4)
    assert seen["programmed_setpoint"] == pytest.approx(setpoint, abs=1e-9)
    assert seen["control_error"] == pytest.approx(error, abs=1e-4)
    assert seen["control_error"] + seen["furnace_temperature"] == pytest.approx(
        seen["programmed_setpoint"], abs=1e-3
    )


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
    # Both Calisto-exported quantities must come from the packed status frame,
    # which is the only place they were confirmed.
    plotted = {s.signature.hex() for s in profile.signals
               if s.name in ("sample_temperature", "heat_flow")}
    assert plotted == {"0008"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
