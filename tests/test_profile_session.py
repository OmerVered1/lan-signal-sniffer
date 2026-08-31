"""Profiles round-trip and decode live; session detection picks a strategy."""

from __future__ import annotations

import json
import struct

import pytest
import synth

from lan_sniffer.protocol.fields import scan_channel
from lan_sniffer.protocol.framer import analyze_flow, group_chunks_by_flow
from lan_sniffer.protocol.profile import (
    DeviceProfile,
    LiveDecoder,
    SignalSpec,
    build_profile,
    load_profiles,
)
from lan_sniffer.protocol.session import (
    MODE_CADENCE,
    MODE_MANUAL,
    MODE_SIGNATURE,
    Calibration,
    Observation,
    SessionDetector,
    calibrate,
)


def c80_profile():
    """Build a C80 profile the way the wizard would, from a capture."""
    chunks = synth.c80_capture()
    result = analyze_flow(next(iter(group_chunks_by_flow(chunks).values())))
    chosen = []
    for channel in result.channels:
        best = scan_channel(channel.payloads).candidates[0]
        name, unit = (
            ("heat_flow", "mW")
            if channel.signature == synth.C80_HF_CMD
            else ("temperature", "degC")
        )
        chosen.append(
            (
                name,
                unit,
                channel.signature,
                channel.mask,
                best.offset,
                best.encoding,
                1.0,
                0.0,
            )
        )
    return build_profile("C80", 1210, result.request_spec, chosen), chunks


# ----- profiles -------------------------------------------------------------


def test_profile_round_trips_through_json(tmp_path):
    profile, _ = c80_profile()
    path = tmp_path / "c80.json"
    profile.save(path)
    again = DeviceProfile.load(path)
    assert again.name == profile.name
    assert again.signal_names == profile.signal_names
    assert again.request_framing.frame_len == profile.request_framing.frame_len
    assert again.signals[0].signature == profile.signals[0].signature


def test_profile_from_a_newer_version_is_refused_not_misread(tmp_path):
    profile, _ = c80_profile()
    raw = profile.to_dict()
    raw["version"] = 999
    path = tmp_path / "future.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="newer version"):
        DeviceProfile.load(path)


def test_unreadable_profiles_are_skipped_not_fatal(tmp_path):
    good, _ = c80_profile()
    good.save(tmp_path / "good.json")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    assert [p.name for p in load_profiles(tmp_path)] == ["C80"]


def test_scale_and_bias_are_applied():
    spec = SignalSpec("t", "K", b"", [], 0, "f32be", scale=1.0, bias=273.15)
    assert spec.convert(25.0) == pytest.approx(298.15)


# ----- live decoding --------------------------------------------------------


def test_live_decoder_recovers_the_transmitted_signal():
    profile, chunks = c80_profile()
    decoder = LiveDecoder(profile)
    samples = decoder.feed(chunks)
    samples.extend(decoder.flush())

    heat = [s.values["heat_flow"] for s in samples if "heat_flow" in s.values]
    assert len(heat) == 120
    assert heat[0] == pytest.approx(synth.heat_flow(0.0), rel=1e-6)
    assert heat[10] == pytest.approx(synth.heat_flow(10.0), rel=1e-6)


def test_live_decoder_emits_one_signal_per_poll_not_a_merged_row():
    # Each poll asks for one channel, so a sample carries one value. Merging
    # them into wide rows is the CSV writer's job, not the decoder's.
    profile, chunks = c80_profile()
    samples = LiveDecoder(profile).feed(chunks)
    assert all(len(s.values) == 1 for s in samples)


def test_live_decoder_handles_a_request_split_across_segments():
    from lan_sniffer.capture.reassembly import TCPReassembler

    profile, _ = c80_profile()
    asm = TCPReassembler(synth.DEVICE_IP)
    chunks = []
    cmd = synth.C80_HF_CMD
    reply = cmd + struct.pack(">f", 321.0)
    seq_c, seq_s = 1000, 5000
    for i in range(12):
        # Deliberately tear the 6-byte request across two segments.
        chunks += asm.add_segment(
            i * 1.0, synth.PEER_IP, 51234, synth.DEVICE_IP, 1210, seq_c, cmd[:4]
        )
        chunks += asm.add_segment(
            i * 1.0, synth.PEER_IP, 51234, synth.DEVICE_IP, 1210, seq_c + 4, cmd[4:]
        )
        seq_c += 6
        chunks += asm.add_segment(
            i * 1.0 + 0.01, synth.DEVICE_IP, 1210, synth.PEER_IP, 51234, seq_s, reply
        )
        seq_s += len(reply)

    decoder = LiveDecoder(profile)
    samples = decoder.feed(chunks)
    assert samples, "a torn request must still decode once its bytes arrive"
    assert samples[0].values["heat_flow"] == pytest.approx(321.0)


def test_live_decoder_ignores_replies_to_unknown_requests():
    profile, _ = c80_profile()
    unknown = bytes.fromhex("000100990099")
    chunks = synth.build_capture(
        [(float(i), unknown, i + 0.01, unknown + struct.pack(">f", 5.0)) for i in range(20)]
    )
    assert LiveDecoder(profile).feed(chunks) == []


# ----- session calibration --------------------------------------------------


def obs(times, signature="aa"):
    return [Observation(ts=t, signature=signature) for t in times]


def test_a_request_seen_only_during_a_run_is_used_as_the_trigger():
    idle = obs([0.0, 1.0, 2.0, 3.0], "poll")
    running = obs([0.0, 1.0], "poll") + obs([1.5, 2.5], "acquire")
    cal = calibrate(idle, running)
    assert cal.mode == MODE_SIGNATURE
    assert cal.trigger_signatures == ["acquire"]


def test_a_faster_poll_rate_is_used_when_the_requests_are_identical():
    idle = obs([i * 10.0 for i in range(10)])
    running = obs([i * 1.0 for i in range(60)])
    cal = calibrate(idle, running)
    assert cal.mode == MODE_CADENCE
    assert cal.idle_rate < cal.rate_threshold < cal.running_rate


def test_silence_while_idle_makes_every_request_a_trigger():
    # With nothing recorded to compare against, every running request looks
    # exclusive. That is the right detector for a genuinely silent instrument,
    # but the explanation has to flag the other reading of an empty capture.
    cal = calibrate([], obs([i * 1.0 for i in range(30)]))
    assert cal.mode == MODE_SIGNATURE
    assert cal.automatic
    assert "not actually connected" in cal.explanation


def test_same_requests_but_only_faster_uses_cadence():
    idle = obs([i * 20.0 for i in range(5)])
    running = obs([i * 1.0 for i in range(60)])
    cal = calibrate(idle, running)
    assert cal.mode == MODE_CADENCE
    assert cal.rate_threshold > 0


def test_indistinguishable_traffic_falls_back_to_manual_and_says_so():
    idle = obs([i * 1.0 for i in range(30)])
    running = obs([i * 1.0 for i in range(30)])
    cal = calibrate(idle, running)
    assert cal.mode == MODE_MANUAL
    assert not cal.automatic
    assert "by hand" in cal.explanation


def test_an_empty_running_capture_is_reported_as_a_setup_mistake():
    cal = calibrate(obs([0.0, 1.0]), [])
    assert cal.mode == MODE_MANUAL
    assert "armed" in cal.explanation


# ----- session detection ----------------------------------------------------


def test_session_starts_only_after_the_streak_is_met():
    cal = Calibration(mode=MODE_SIGNATURE, trigger_signatures=["go"], start_streak=3)
    det = SessionDetector(cal)
    assert det.observe(Observation(0.0, "go")) is None
    assert det.observe(Observation(1.0, "go")) is None
    assert det.observe(Observation(2.0, "go")) == "start"
    assert det.running


def test_a_lone_stray_request_does_not_open_a_session():
    cal = Calibration(mode=MODE_SIGNATURE, trigger_signatures=["go"], start_streak=3)
    det = SessionDetector(cal)
    det.observe(Observation(0.0, "go"))
    for i in range(20):
        det.observe(Observation(1.0 + i, "idle"))
    assert not det.running


def test_a_trigger_interleaved_with_other_polls_still_starts_a_session():
    # The trigger is one step of a rotation, so it never arrives twice in a row.
    # Requiring consecutive hits would mean a session could never start.
    cal = Calibration(mode=MODE_SIGNATURE, trigger_signatures=["go"], start_streak=3)
    det = SessionDetector(cal)
    events = []
    for i in range(8):
        events.append(det.observe(Observation(i * 2.0, "go")))
        events.append(det.observe(Observation(i * 2.0 + 1.0, "other")))
    assert "start" in events
    assert det.running


def test_triggers_spread_far_apart_do_not_accumulate_into_a_start():
    # Three hits an hour apart are not an experiment starting.
    cal = Calibration(
        mode=MODE_SIGNATURE,
        trigger_signatures=["go"],
        start_streak=3,
        quiet_seconds=30.0,
    )
    det = SessionDetector(cal)
    for i in range(5):
        det.observe(Observation(i * 3600.0, "go"))
    assert not det.running


def test_session_ends_after_the_quiet_period():
    cal = Calibration(
        mode=MODE_SIGNATURE,
        trigger_signatures=["go"],
        start_streak=1,
        quiet_seconds=30.0,
    )
    det = SessionDetector(cal)
    det.observe(Observation(0.0, "go"))
    assert det.tick(20.0) is None
    assert det.tick(31.0) == "stop"
    assert not det.running


def test_manual_start_wins_over_the_detector():
    det = SessionDetector(Calibration(mode=MODE_MANUAL))
    det.start(0.0)
    assert det.running
    det.stop()
    assert not det.running


def test_manual_control_suspends_automatic_stopping():
    cal = Calibration(mode=MODE_SIGNATURE, trigger_signatures=["go"], quiet_seconds=1.0)
    det = SessionDetector(cal)
    det.start(0.0)
    assert det.tick(1000.0) is None, "a hand-started session must not auto-close"
    det.resume_automatic()
    det.observe(Observation(1001.0, "go"))


def test_cadence_mode_starts_when_polling_speeds_up():
    cal = Calibration(mode=MODE_CADENCE, rate_threshold=0.5, start_streak=3)
    det = SessionDetector(cal, window_seconds=20.0)
    events = [det.observe(Observation(i * 1.0, "poll")) for i in range(10)]
    assert "start" in events


def test_cadence_mode_ignores_slow_idle_polling():
    cal = Calibration(mode=MODE_CADENCE, rate_threshold=0.5, start_streak=3)
    det = SessionDetector(cal, window_seconds=20.0)
    for i in range(10):
        det.observe(Observation(i * 10.0, "poll"))  # 0.1/s, well under threshold
    assert not det.running


def test_calibration_round_trips_through_a_profile(tmp_path):
    profile, _ = c80_profile()
    cal = calibrate(obs([0.0, 5.0]), obs([0.0, 1.0], "acquire"))
    profile.session = cal.to_dict()
    profile.save(tmp_path / "p.json")
    again = DeviceProfile.load(tmp_path / "p.json")
    assert Calibration.from_dict(again.session).mode == cal.mode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
