"""Session output: wide CSV rows, and a raw sidecar that survives re-decoding."""

from __future__ import annotations

import csv

import pytest
import synth

from lan_sniffer.protocol.profile import LiveDecoder
from lan_sniffer.writers.csv_writer import SessionCSVWriter
from lan_sniffer.writers.raw_writer import RawWriter, read_raw, read_raw_header
from test_profile_session import c80_profile


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.reader(fh))


# ----- CSV ------------------------------------------------------------------


def test_header_carries_units():
    path = None

    def build(tmp):
        return SessionCSVWriter(tmp, ["hf", "t"], units={"hf": "mW", "t": "degC"})

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "s.csv"
        build(path).close()
        assert read_csv(path)[0] == ["timestamp_utc", "elapsed_s", "hf (mW)", "t (degC)"]


def test_samples_arriving_one_signal_at_a_time_merge_into_one_row(tmp_path):
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["hf", "t"]) as w:
        w.add(1000.0, {"hf": 300.0})
        w.add(1000.5, {"t": 150.0})
    rows = read_csv(path)
    assert len(rows) == 2  # header plus one data row
    assert rows[1][2:] == ["300", "150"]


def test_a_repeated_signal_starts_the_next_row(tmp_path):
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["hf", "t"]) as w:
        w.add(1000.0, {"hf": 300.0})
        w.add(1000.5, {"t": 150.0})
        w.add(1001.0, {"hf": 305.0})
        w.add(1001.5, {"t": 151.0})
    rows = read_csv(path)
    assert [r[2:] for r in rows[1:]] == [["300", "150"], ["305", "151"]]


def test_a_missing_signal_does_not_stall_the_file(tmp_path):
    # If a channel drops out, the row must still be written once its budget
    # expires, leaving the missing value blank rather than blocking for ever.
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["hf", "t"], row_timeout=2.0) as w:
        w.add(1000.0, {"hf": 300.0})
        w.add(1010.0, {"t": 150.0})
    rows = read_csv(path)
    assert rows[1][2:] == ["300", ""]
    assert rows[2][2:] == ["", "150"], "the late sample belongs to its own row"


def test_elapsed_time_is_measured_from_the_first_sample(tmp_path):
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["hf"]) as w:
        w.add(5000.0, {"hf": 1.0})
        w.add(5012.5, {"hf": 2.0})
    rows = read_csv(path)
    assert rows[1][1] == "0.000"
    assert rows[2][1] == "12.500"


def test_absolute_timestamp_is_written_as_wall_clock(tmp_path):
    # This column is the reason for sniffing rather than polling: it lets a C80
    # file be aligned to a Keithley file without re-deriving an offset.
    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["hf"]) as w:
        w.add(1_700_000_000.25, {"hf": 1.0})
    assert read_csv(path)[1][0].startswith("2023-11-14 22:13:20.250")


def test_partial_row_is_written_on_close(tmp_path):
    path = tmp_path / "s.csv"
    w = SessionCSVWriter(path, ["hf", "t"])
    w.add(1000.0, {"hf": 300.0})
    w.close()
    assert read_csv(path)[1][2:] == ["300", ""]


# ----- raw sidecar ----------------------------------------------------------


def test_raw_sidecar_round_trips_every_chunk(tmp_path):
    chunks = synth.c80_capture(n_cycles=20)
    path = tmp_path / "s.raw.jsonl"
    with RawWriter(path, device_ip=synth.DEVICE_IP, device_port=1210) as w:
        w.add(chunks)
    back = list(read_raw(path))
    assert len(back) == len(chunks)
    assert [c.data for c in back] == [c.data for c in chunks]
    assert [c.ts for c in back] == [c.ts for c in chunks]
    assert [c.direction for c in back] == [c.direction for c in chunks]


def test_re_decoding_a_sidecar_reproduces_the_session(tmp_path):
    # The point of keeping raw bytes: a session recorded under a wrong profile
    # can be decoded again without repeating the experiment.
    profile, chunks = c80_profile()
    path = tmp_path / "s.raw.jsonl"
    with RawWriter(path, device_ip=synth.DEVICE_IP) as w:
        w.add(chunks)

    live = LiveDecoder(profile).feed(chunks)
    replayed = LiveDecoder(profile).feed(read_raw(path))
    assert [s.values for s in replayed] == [s.values for s in live]


def test_gap_markers_survive_the_round_trip(tmp_path):
    from lan_sniffer.capture.reassembly import FlowKey, StreamChunk

    chunk = StreamChunk(
        ts=1.0,
        flow=FlowKey("10.0.0.1", 5000, 1210),
        direction="c2s",
        data=b"\x01\x02",
        stream_offset=8,
        gap_before=12,
    )
    path = tmp_path / "s.raw.jsonl"
    with RawWriter(path, device_ip="10.0.0.2") as w:
        w.add([chunk])
    assert list(read_raw(path))[0].gap_before == 12


def test_header_records_what_was_captured(tmp_path):
    path = tmp_path / "s.raw.jsonl"
    with RawWriter(path, device_ip="10.0.0.2", device_port=1210, note="C80 run 3") as w:
        w.add([])
    header = read_raw_header(path)
    assert header["device_ip"] == "10.0.0.2"
    assert header["note"] == "C80 run 3"


def test_a_file_that_is_not_a_capture_is_rejected_clearly(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some notes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a raw capture file"):
        list(read_raw(path))


def test_a_newer_sidecar_format_is_refused(tmp_path):
    path = tmp_path / "s.raw.jsonl"
    path.write_text('{"format": "lan-sniffer-raw", "version": 99}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="newer version"):
        list(read_raw(path))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
