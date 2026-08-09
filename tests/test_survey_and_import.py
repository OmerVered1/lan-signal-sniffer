"""Survey export and profile import: the round trip through outside analysis.

The workflow these support is: record an unidentified instrument, hand the export
to someone (or something) that also has the vendor software's own export of the
same run, and import the config that comes back. Both ends of that trip have to
hold up without the app being there to explain itself — the export has to be
self-describing, and the import has to refuse a config that would quietly record
wrong numbers.
"""

from __future__ import annotations

import json

import pytest
import synth

from lan_sniffer.protocol.framer import FramingSpec
from lan_sniffer.protocol.profile import DeviceProfile, SignalSpec, build_profile
from lan_sniffer.writers.survey import build_survey, write_survey


# ----- survey export --------------------------------------------------------


def test_survey_finds_a_column_for_the_real_signal():
    survey = build_survey(synth.c80_capture(n_cycles=40))
    names = [c.name for c in survey.columns]
    # Two channels, each with the float at offset 6.
    assert "ch0@6:f32be" in names
    assert "ch1@6:f32be" in names


def test_survey_keeps_the_raw_bytes_for_anything_it_read_wrongly():
    # The whole point of exporting to an outside analyst is that they may know
    # something the scan does not. Without the raw bytes they could only choose
    # between this app's guesses.
    survey = build_survey(synth.c80_capture(n_cycles=40))
    assert "ch0:hex" in [c.name for c in survey.columns]
    hex_values = [
        v["ch0:hex"] for _ts, v in survey.samples if "ch0:hex" in v
    ]
    assert hex_values
    assert all(len(h) == 20 for h in hex_values), "10 reply bytes as 20 hex chars"


def test_survey_exports_alternatives_not_only_the_top_pick():
    # A reading the scan outranked is not a reading it rejected, and excluding
    # it would hide the one that turns out to be right.
    survey = build_survey(synth.c80_capture(n_cycles=40))
    ch0 = [c for c in survey.columns if c.channel_index == 0 and not c.raw_hex]
    encodings = {c.encoding for c in ch0}
    assert len(ch0) > 1
    assert encodings != {"f32be"}, "only the winner was exported"


def test_survey_values_are_the_transmitted_ones():
    survey = build_survey(synth.c80_capture(n_cycles=30))
    heat = [
        v["ch0@6:f32be"] for _ts, v in survey.samples if "ch0@6:f32be" in v
    ]
    assert len(heat) == 30
    assert heat[4] == pytest.approx(synth.heat_flow(4.0), rel=1e-6)


def test_survey_rows_carry_wall_clock_time(tmp_path):
    # Aligning against the vendor export is the entire point; without real
    # timestamps the export is unusable for that.
    offset = 1_700_000_000.0
    import struct

    exchanges = [
        (
            offset + i,
            synth.C80_HF_CMD,
            offset + i + 0.01,
            synth.C80_HF_CMD + struct.pack(">f", synth.heat_flow(i)),
        )
        for i in range(20)
    ]
    survey = build_survey(synth.build_capture(exchanges))
    csv_path, _json_path = write_survey(survey, tmp_path / "s.csv")
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    assert rows[1].startswith("2023-11-14 22:13:20")


def test_export_writes_both_files(tmp_path):
    survey = build_survey(synth.c80_capture(n_cycles=25))
    csv_path, json_path = write_survey(
        survey, tmp_path / "s.csv", device_ip="169.254.93.1", device_port=1210
    )
    assert csv_path.exists() and json_path.exists()
    meta = json.loads(json_path.read_text(encoding="utf-8"))
    assert meta["device"]["ip"] == "169.254.93.1"
    assert len(meta["channels"]) == 2
    assert meta["channels"][0]["median_period_s"] == pytest.approx(1.0, abs=1e-6)


def test_metadata_explains_how_to_read_the_csv(tmp_path):
    survey = build_survey(synth.c80_capture(n_cycles=25))
    _csv, json_path = write_survey(survey, tmp_path / "s.csv")
    meta = json.loads(json_path.read_text(encoding="utf-8"))
    guidance = " ".join(meta["how_to_read_this"]).lower()
    assert "timestamp_utc" in guidance
    assert "vendor" in guidance or "instrument software" in guidance
    # Every data column must be described, or the CSV is a wall of numbers.
    described = {c["column"] for c in meta["columns"]}
    assert described == set(survey.column_names)


def test_metadata_carries_the_config_schema(tmp_path):
    # So whoever analyses the CSV can hand back something importable without
    # being sent the format separately.
    survey = build_survey(synth.c80_capture(n_cycles=25))
    _csv, json_path = write_survey(survey, tmp_path / "s.csv")
    schema = json.loads(json_path.read_text(encoding="utf-8"))["profile_schema"]
    assert "f32be" in schema["encodings"]
    example = schema["example"]
    assert {"name", "device_port", "signals", "request_framing"} <= set(example)
    assert {"name", "unit", "offset", "encoding", "scale"} <= set(example["signals"][0])


def test_survey_of_silence_says_so_rather_than_failing():
    survey = build_survey([])
    assert survey.columns == []
    assert any("no traffic" in w for w in survey.warnings)


def test_a_schema_shaped_config_actually_imports(tmp_path):
    """The documented example must be a real, importable profile.

    A schema that drifts from what the loader accepts is worse than none: it
    sends the analyst confidently in the wrong direction.
    """
    survey = build_survey(synth.c80_capture(n_cycles=25))
    _csv, json_path = write_survey(survey, tmp_path / "s.csv")
    meta = json.loads(json_path.read_text(encoding="utf-8"))

    example = meta["profile_schema"]["example"]
    # Fill the placeholder prose with values a real analyst would supply.
    config = {
        "version": 1,
        "name": example["name"],
        "device_port": example["device_port"],
        "interaction": example["interaction"],
        "request_framing": {"mode": "fixed", "frame_len": 6},
        "signals": [
            {
                "name": "heat_flow",
                "unit": "mW",
                "signature": meta["channels"][0]["request_hex"].replace(".", "0"),
                "mask": meta["channels"][0]["request_mask"],
                "offset": 6,
                "encoding": "f32be",
                "scale": 1.0,
                "bias": 0.0,
            }
        ],
        "session": {"mode": "manual"},
    }
    path = tmp_path / "from_analysis.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    profile = DeviceProfile.load(path)
    assert profile.validate() == []


# ----- profile validation ---------------------------------------------------


def good_profile() -> DeviceProfile:
    return build_profile(
        "Test",
        1210,
        FramingSpec(mode="fixed", frame_len=6),
        [("hf", "mW", synth.C80_HF_CMD, [True] * 6, 6, "f32be", 1.0, 0.0)],
    )


def test_a_sound_profile_reports_no_problems():
    assert good_profile().validate() == []


def test_unknown_encoding_is_rejected_with_the_valid_ones_listed():
    profile = good_profile()
    profile.signals[0].encoding = "float32"  # a plausible-looking guess
    problems = profile.validate()
    assert problems
    assert "f32be" in problems[0]


def test_ascii_encoding_form_is_checked():
    profile = good_profile()
    profile.signals[0].encoding = "ascii#first"
    assert any("ascii#N" in p for p in profile.validate())


def test_mask_length_must_match_the_signature():
    profile = good_profile()
    profile.signals[0].mask = [True, True]
    assert any("one-to-one" in p for p in profile.validate())


def test_duplicate_signal_names_are_rejected():
    profile = good_profile()
    profile.signals.append(
        SignalSpec("hf", "mW", synth.C80_T_CMD, [True] * 6, 6, "f32be")
    )
    assert any("used 2 times" in p for p in profile.validate())


def test_a_request_response_signal_needs_a_signature():
    profile = good_profile()
    profile.signals[0].signature = b""
    profile.signals[0].mask = []
    assert any("request signature" in p for p in profile.validate())


def test_a_zero_scale_is_caught():
    # Silently records every reading as the bias; nothing would look broken.
    profile = good_profile()
    profile.signals[0].scale = 0.0
    assert any("scale is 0" in p for p in profile.validate())


def test_a_push_profile_without_response_framing_is_rejected():
    profile = good_profile()
    profile.interaction = "server_push"
    profile.signals[0].signature = b""
    profile.signals[0].mask = []
    assert any("response_framing" in p for p in profile.validate())


def test_every_problem_is_reported_not_just_the_first():
    # Fixing an externally written config one error per round trip is miserable.
    profile = good_profile()
    profile.name = ""
    profile.signals[0].encoding = "nonsense"
    profile.signals[0].scale = 0.0
    profile.signals[0].offset = -1
    assert len(profile.validate()) >= 4


def test_a_profile_with_no_signals_is_rejected():
    profile = good_profile()
    profile.signals = []
    assert any("no signals" in p for p in profile.validate())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
