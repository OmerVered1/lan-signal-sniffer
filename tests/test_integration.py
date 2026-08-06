"""End to end: raw packets in, named and unit-bearing CSV out.

Each test walks the whole path — reassembly, framing, field scanning, profile,
live decode, session detection, CSV — because that is the only way to catch a
seam where two correct components disagree about what they are passing.
"""

from __future__ import annotations

import csv
import struct
from pathlib import Path

import pytest
import synth

from lan_sniffer.capture.reassembly import C2S
from lan_sniffer.protocol.fields import scan_channel
from lan_sniffer.protocol.framer import analyze_flow, group_chunks_by_flow, split_frames
from lan_sniffer.protocol.profile import DeviceProfile, LiveDecoder, build_profile
from lan_sniffer.protocol.session import (
    MODE_SIGNATURE,
    Observation,
    SessionDetector,
    calibrate_from_requests,
)
from lan_sniffer.writers.csv_writer import SessionCSVWriter
from lan_sniffer.writers.raw_writer import RawWriter, read_raw

PROFILE_DIR = Path(__file__).resolve().parents[1] / "profiles"


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.reader(fh))


# ----- the profiles that ship with the app ----------------------------------


def test_shipped_c80_profile_decodes_c80_traffic():
    # The file is hand-written from bench-verified command bytes, so this is
    # the check that it was transcribed correctly.
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_c80.json")
    decoder = LiveDecoder(profile)
    samples = decoder.feed(synth.c80_capture(n_cycles=30))
    # A reply is only complete once the next request goes out, so the final
    # sample is still held when the capture ends.
    tail = decoder.flush()
    if tail:
        samples.append(tail)

    heat = [s.values["heat_flow"] for s in samples if "heat_flow" in s.values]
    temp = [
        s.values["sample_temperature"]
        for s in samples
        if "sample_temperature" in s.values
    ]
    assert len(heat) == 30 and len(temp) == 30
    assert heat[5] == pytest.approx(synth.heat_flow(5.0), rel=1e-6)
    assert temp[5] == pytest.approx(synth.temperature(5.0), rel=1e-6)


def test_shipped_profiles_all_load_and_are_self_consistent():
    for path in sorted(PROFILE_DIR.glob("*.json")):
        profile = DeviceProfile.load(path)
        assert profile.signals, f"{path.name} declares no signals"
        assert len(set(profile.signal_names)) == len(profile.signals), (
            f"{path.name} has duplicate signal names, which would collide as "
            "CSV columns"
        )
        for signal in profile.signals:
            assert len(signal.mask) == len(signal.signature), (
                f"{path.name}: {signal.name} has a mask of the wrong length"
            )


def test_drop_profile_carries_the_third_channel():
    profile = DeviceProfile.load(PROFILE_DIR / "alexsys_drop.json")
    assert "external_temperature" in profile.signal_names
    external = [s for s in profile.signals if s.name == "external_temperature"][0]
    # Confirmed on the bench as argument 0005, not the 0003 that Calisto's
    # on-screen labels imply.
    assert external.signature.hex() == "000100080005"


# ----- discovery to recording, with no prior knowledge ----------------------


def discover(chunks):
    """Everything the wizard does, minus the human: analyse, scan, pick best."""
    analysis = analyze_flow(next(iter(group_chunks_by_flow(chunks).values())))
    chosen = []
    for i, channel in enumerate(analysis.channels):
        best = scan_channel(channel.payloads).candidates[0]
        chosen.append(
            (
                f"signal_{i}",
                "unit",
                channel.signature,
                channel.mask,
                best.offset,
                best.encoding,
                1.0,
                0.0,
            )
        )
    return build_profile(
        "discovered", 1210, analysis.request_spec, chosen,
        interaction=analysis.interaction,
        response_framing=analysis.response_spec,
    ), analysis


@pytest.mark.parametrize(
    "make_capture,expected_signals",
    [
        (synth.c80_capture, 2),
        (synth.scpi_capture, 2),
        (synth.length_prefixed_capture, 3),
        (synth.push_capture, 1),
    ],
)
def test_a_device_is_decoded_without_any_prior_knowledge(
    make_capture, expected_signals
):
    chunks = make_capture()
    profile, _ = discover(chunks)
    assert len(profile.signals) == expected_signals
    samples = LiveDecoder(profile).feed(chunks)
    assert samples, "a discovered profile must decode the traffic it came from"


def test_the_recorded_csv_matches_what_was_transmitted(tmp_path):
    chunks = synth.c80_capture(n_cycles=40)
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_c80.json")

    path = tmp_path / "session.csv"
    units = {s.name: s.unit for s in profile.signals}
    decoder = LiveDecoder(profile)
    with SessionCSVWriter(path, profile.signal_names, units) as writer:
        for sample in decoder.feed(chunks):
            writer.add(sample.ts, sample.values)
        tail = decoder.flush()
        if tail:
            writer.add(tail.ts, tail.values)

    rows = read_csv(path)
    assert rows[0] == [
        "timestamp_utc",
        "elapsed_s",
        "heat_flow (mW)",
        "sample_temperature (degC)",
    ]
    assert len(rows) - 1 == 40, "one row per poll cycle"
    for i, row in enumerate(rows[1:]):
        assert float(row[2]) == pytest.approx(synth.heat_flow(i * 1.0), rel=1e-6)
        assert float(row[3]) == pytest.approx(synth.temperature(i * 1.0), rel=1e-6)


def test_absolute_timestamps_survive_into_the_csv(tmp_path):
    # The reason to sniff rather than poll: samples carry the capture clock, so
    # a C80 file lines up with a Keithley file without deriving an offset.
    offset = 1_700_000_000.0
    exchanges = [
        (
            offset + i,
            synth.C80_HF_CMD,
            offset + i + 0.01,
            synth.C80_HF_CMD + struct.pack(">f", synth.heat_flow(i)),
        )
        for i in range(20)
    ]
    profile = DeviceProfile.load(PROFILE_DIR / "setaram_c80.json")
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["heat_flow"], {"heat_flow": "mW"}) as writer:
        for sample in LiveDecoder(profile).feed(synth.build_capture(exchanges)):
            writer.add(sample.ts, sample.values)
    rows = read_csv(path)
    assert rows[1][0].startswith("2023-11-14 22:13:20")
    assert rows[2][1] == "1.000"


# ----- session detection driving the recording ------------------------------


def requests_from(chunks):
    """Pull request frames out of a capture, the way the app does live."""
    from lan_sniffer.protocol.framer import TimedStream

    out = []
    for chunk in chunks:
        if chunk.direction != C2S:
            continue
        stream = TimedStream()
        stream.append(chunk)
        for frame in split_frames(stream, _FIXED6):
            out.append((chunk.ts, frame.data))
    return out


from lan_sniffer.protocol.framer import FramingSpec  # noqa: E402

_FIXED6 = FramingSpec(mode="fixed", frame_len=6)


def test_calibration_then_detection_opens_a_session_at_the_right_moment():
    # Idle: the vendor software polls temperature only. Running: it also asks
    # for heat flow. That extra request is what a run looks like on the wire.
    idle_chunks = synth.build_capture(
        [
            (
                float(i),
                synth.C80_T_CMD,
                i + 0.01,
                synth.C80_T_CMD + struct.pack(">f", 25.0),
            )
            for i in range(40)
        ]
    )
    running_chunks = synth.c80_capture(n_cycles=40)

    calibration = calibrate_from_requests(
        requests_from(idle_chunks), requests_from(running_chunks)
    )
    assert calibration.mode == MODE_SIGNATURE
    assert calibration.trigger_signatures == [synth.C80_HF_CMD.hex()]

    detector = SessionDetector(calibration)
    events = []
    for ts, frame in requests_from(idle_chunks):
        events.append(detector.observe(Observation(ts, calibration.signature_of(frame))))
    assert not detector.running, "idle traffic must not open a session"

    for ts, frame in requests_from(running_chunks):
        events.append(detector.observe(Observation(ts, calibration.signature_of(frame))))
    assert "start" in events
    assert detector.running


def test_session_closes_when_the_experiment_stops():
    calibration = calibrate_from_requests(
        [(float(i), synth.C80_T_CMD) for i in range(20)],
        [(float(i), synth.C80_HF_CMD) for i in range(20)],
    )
    detector = SessionDetector(calibration)
    for i in range(20):
        detector.observe(Observation(float(i), calibration.signature_of(synth.C80_HF_CMD)))
    assert detector.running
    assert detector.tick(19.0 + calibration.quiet_seconds + 1) == "stop"


# ----- recovery from a bad profile ------------------------------------------


def test_a_session_recorded_under_a_wrong_profile_can_be_re_decoded(tmp_path):
    """The raw sidecar has to make a mis-identification recoverable.

    This is the failure the sidecar exists for: a signal identified at the wrong
    offset produces a useless CSV, and without the raw bytes the only remedy is
    to run the experiment again.
    """
    chunks = synth.c80_capture(n_cycles=30)
    raw_path = tmp_path / "s.raw.jsonl"
    with RawWriter(raw_path, device_ip=synth.DEVICE_IP, device_port=1210) as w:
        w.add(chunks)

    good = DeviceProfile.load(PROFILE_DIR / "setaram_c80.json")
    wrong = DeviceProfile.load(PROFILE_DIR / "setaram_c80.json")
    for signal in wrong.signals:
        signal.offset = 2  # reads the request echo instead of the measurement

    bad = [
        s.values["heat_flow"]
        for s in LiveDecoder(wrong).feed(read_raw(raw_path))
        if "heat_flow" in s.values
    ]
    expected = [synth.heat_flow(i * 1.0) for i in range(len(bad))]
    assert bad, "the wrong profile still writes a plausible-looking CSV"
    assert not any(
        b == pytest.approx(e, rel=1e-6) for b, e in zip(bad, expected)
    ), "the wrong profile must genuinely produce wrong numbers, not near misses"

    fixed = LiveDecoder(good).feed(read_raw(raw_path))
    heat = [s.values["heat_flow"] for s in fixed if "heat_flow" in s.values]
    assert len(heat) == 30
    assert heat[7] == pytest.approx(synth.heat_flow(7.0), rel=1e-6)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
