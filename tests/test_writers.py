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


# ----- two instruments, one file --------------------------------------------


def test_the_sidecar_remembers_which_instrument_each_chunk_came_from(tmp_path):
    """A flow names the PC, which is the same for every device being watched.

    Both instruments in a coupled rig record into one sidecar. Without the
    device on each record their traffic is indistinguishable afterwards, and
    decoding the file would analyse two instruments as one.
    """
    from lan_sniffer.capture.reassembly import TCPReassembler
    from lan_sniffer.writers.raw_writer import RawWriter, read_raw

    oven = TCPReassembler("169.254.60.1")
    spectrometer = TCPReassembler("172.16.0.1")
    chunks = []
    for i in range(4):
        chunks += oven.add_segment(
            float(i), "10.0.0.5", 51234, "169.254.60.1", 1210, 1000 + i * 2, b"ov"
        )
        chunks += spectrometer.add_segment(
            i + 0.5, "10.0.0.5", 51235, "172.16.0.1", 30000, 2000 + i * 2, b"ms"
        )

    path = tmp_path / "both.raw.jsonl"
    with RawWriter(path, device_ip="169.254.60.1, 172.16.0.1") as writer:
        writer.add(chunks)

    back = list(read_raw(path))
    assert len(back) == len(chunks)
    assert {c.device_ip for c in back} == {"169.254.60.1", "172.16.0.1"}
    assert all(c.data == b"ov" for c in back if c.device_ip == "169.254.60.1")
    assert all(c.data == b"ms" for c in back if c.device_ip == "172.16.0.1")


def test_two_instruments_are_not_analysed_as_one(tmp_path):
    from lan_sniffer.capture.reassembly import TCPReassembler
    from lan_sniffer.protocol.framer import group_chunks_by_flow

    oven = TCPReassembler("169.254.60.1")
    spectrometer = TCPReassembler("172.16.0.1")
    chunks = []
    for i in range(4):
        # Same peer, same peer port, same device port: only the device differs.
        chunks += oven.add_segment(
            float(i), "10.0.0.5", 51234, "169.254.60.1", 1210, 1000 + i * 2, b"ov"
        )
        chunks += spectrometer.add_segment(
            i + 0.5, "10.0.0.5", 51234, "172.16.0.1", 1210, 2000 + i * 2, b"ms"
        )

    assert len(group_chunks_by_flow(chunks)) == 2, "one bucket would merge them"


def test_an_older_reading_does_not_join_the_row_that_is_open(tmp_path):
    """A device that answers with a short history delivers old after new.

    Folding one of those into the open row stamps it with a moment it did not
    happen at - and the readings either side of it are half a minute apart.
    """
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temperature", "concentration"]) as w:
        w.add(1000.0, {"temperature": 20.0})
        w.add(1000.5, {"temperature": 20.1})
        # Twenty-four seconds older than the open row.
        w.add(976.0, {"concentration": 1.5})
        w.add(1001.0, {"temperature": 20.2})

    rows = path.read_text(encoding="utf-8").splitlines()[1:]
    stamped = [r.split(",")[0] for r in rows if "1.5" in r]
    assert stamped, "the old reading must still be written"
    assert stamped[0].endswith("16:16.000"), (
        f"it must carry its own time, not the open row's: {stamped[0]}"
    )


def test_rows_are_in_time_order_when_the_session_closes(tmp_path):
    """One instrument's results arrive seconds after the moment they describe.

    Written as they arrive, the file is out of order and its elapsed column
    counts backwards in places. Nothing is changed but the order: every row
    keeps its own timestamp and its own values.
    """
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temperature", "concentration"]) as w:
        w.add(1000.0, {"temperature": 20.0})
        w.add(1008.0, {"temperature": 20.2})
        w.add(1004.0, {"concentration": 1.5})   # arrives late, belongs between
        w.add(1012.0, {"temperature": 20.3})

    rows = [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]
    stamps = [r[0] for r in rows]
    assert stamps == sorted(stamps), stamps
    elapsed = [float(r[1]) for r in rows]
    assert elapsed == sorted(elapsed)
    assert elapsed[0] == 0.0, "elapsed counts from the earliest row"
    assert min(elapsed) >= 0.0, "no row may sit before the start of the run"
    assert any("1.5" in r for r in rows), "the late reading is still there"


def test_a_file_already_in_order_is_left_alone(tmp_path):
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temperature"]) as w:
        for i in range(4):
            w.add(1000.0 + i, {"temperature": 20.0 + i})
    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 5
    assert [float(r.split(",")[1]) for r in rows[1:]] == [0.0, 1.0, 2.0, 3.0]


# ----- two instruments that report at different rates ------------------------


def test_a_slower_instrument_still_appears_on_every_row(tmp_path):
    """The complaint this fixes: an oven at 1 Hz and an analyser every 7 s
    shared a row twice in seventy-two."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["oven.temp", "ms.o2"]) as w:
        w.add(0.0, {"ms.o2": 72.1})
        for i in range(1, 8):
            w.add(float(i), {"oven.temp": 100.0 + i})
        w.add(8.0, {"ms.o2": 72.4})

    rows = [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]
    with_both = [r for r in rows if r[2] and r[3]]
    assert len(with_both) >= 6, rows
    # The carried value is the one actually reported, not an average of the two.
    assert all(r[3] in ("72.1", "72.4") for r in rows if r[3])


def test_a_reading_is_not_carried_once_it_is_stale(tmp_path):
    """An instrument that stops must go blank, not hold its last value.

    Holding it would read as an instrument still answering, which is the one
    thing worse than a gap.
    """
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["oven.temp", "ms.o2"]) as w:
        w.add(0.0, {"ms.o2": 72.1})
        w.add(1.0, {"ms.o2": 72.2})   # cadence: about one second
        for i in range(2, 40):
            w.add(float(i), {"oven.temp": 100.0 + i})

    rows = [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]
    assert rows[-1][3] == "", "a long-dead signal must not still be reported"
    filled = [r for r in rows if r[3]]
    assert len(filled) < len(rows), "and it must have stopped at some point"


def test_a_reading_is_never_carried_backwards(tmp_path):
    """It would claim a measurement before the instrument took it."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["oven.temp", "ms.o2"]) as w:
        w.add(0.0, {"oven.temp": 100.0})
        w.add(1.0, {"oven.temp": 101.0})
        w.add(2.0, {"ms.o2": 72.0})

    rows = [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]
    assert rows[0][3] == "", "the first rows predate the reading"


def test_carrying_can_be_turned_off_for_only_what_was_measured(tmp_path):
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["a", "b"], carry_forward=False) as w:
        w.add(0.0, {"b": 5.0})
        for i in range(1, 5):
            w.add(float(i), {"a": float(i)})

    rows = [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]
    # A row may still hold both when the two arrived inside its time budget -
    # that is the row batching, not a repeat. What must not happen is the one
    # measurement of b appearing on more than one row.
    assert sum(1 for r in rows if r[3]) == 1, rows


# ----- one row per experiment sample -----------------------------------------


def rows_of(path):
    return [r.split(",") for r in path.read_text(encoding="utf-8").splitlines()[1:]]


def test_a_row_is_written_when_the_anchoring_signal_reports(tmp_path):
    """The rate belongs to the signal: a Setaram answers its status frame at
    whatever rate Calisto was told to log at."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        w.add(0.0, {"o2": 72.0})
        for i in range(4):
            w.add(float(i) * 3, {"temp": 100.0 + i})

    rows = rows_of(path)
    assert len(rows) == 4, rows
    assert [r[1] for r in rows] == ["0.000", "3.000", "6.000", "9.000"]


def test_the_anchoring_signal_is_never_a_held_value(tmp_path):
    """It is the reading the row exists for; holding it would resample the one
    measurement that does not need it."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        w.add(0.0, {"o2": 72.0})
        w.add(0.0, {"temp": 100.0})
        w.add(3.0, {"temp": 101.5})

    assert [r[2] for r in rows_of(path)] == ["100", "101.5"]


def test_a_faster_signal_contributes_its_last_reading_before_the_row(tmp_path):
    """No averaging: every cell stays a number the instrument actually sent."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "fast"], follow="temp") as w:
        w.add(0.0, {"fast": 1.0})
        w.add(0.0, {"temp": 100.0})
        for i in range(1, 10):
            w.add(i * 0.1, {"fast": 1.0 + i})
        w.add(1.0, {"temp": 101.0})

    rows = rows_of(path)
    assert rows[-1][3] == "10", "the newest reading before the row, not a mean"


def test_no_row_is_written_before_every_signal_has_reported(tmp_path):
    """Emitting them would put back the empty cells anchoring exists to remove."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        w.add(0.0, {"temp": 100.0})
        w.add(3.0, {"temp": 101.0})
        assert w.waiting_for == ["o2"]
        w.add(4.0, {"o2": 72.0})
        w.add(6.0, {"temp": 102.0})

    rows = rows_of(path)
    assert len(rows) == 1, "only the row after o2 first reported"
    assert all(cell for cell in rows[0]), rows[0]


def test_a_signal_that_never_reports_does_not_silence_the_file(tmp_path):
    """A misconfigured device must not cost the whole recording."""
    from lan_sniffer.writers.csv_writer import SETTLE_S, SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "never"], follow="temp") as w:
        w.add(0.0, {"temp": 100.0})
        w.add(SETTLE_S - 1, {"temp": 101.0})
        assert not rows_of(path), "still hoping it will answer"
        w.add(SETTLE_S + 1, {"temp": 102.0})

    rows = rows_of(path)
    assert len(rows) == 1, "the wait ends once nothing new is arriving"
    assert rows[0][3] == "", "and the gap shows rather than being invented"


def test_the_wait_ends_as_soon_as_the_last_signal_joins(tmp_path):
    """The common case: an analyser simply slower to answer than the oven."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        for i in range(12):
            w.add(float(i), {"temp": 100.0 + i})
            if i == 3:
                w.add(float(i), {"o2": 72.0})

    rows = rows_of(path)
    # From the row after o2 first reported - the one at i == 3 was written
    # before it, in the same instant.
    assert len(rows) == 8, len(rows)
    assert all(all(cell for cell in r) for r in rows)


def test_a_signal_that_stops_goes_blank_rather_than_repeating(tmp_path):
    """A dead instrument must not look alive."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        # Interleaved in time, as a real run delivers them: the analyser
        # answers twice and then stops while the oven carries on.
        for i in range(40):
            w.add(float(i), {"temp": 100.0 + i})
            if i < 2:
                w.add(float(i), {"o2": 72.0 + i})

    rows = rows_of(path)
    assert rows[0][3], "it was reporting at the start"
    assert rows[-1][3] == "", "and had stopped by the end"


def test_a_late_older_reading_does_not_displace_a_newer_one(tmp_path):
    """A device answering with a short history delivers old after new."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        w.add(5.0, {"o2": 72.5})
        w.add(1.0, {"o2": 70.0})          # older, arriving late
        w.add(6.0, {"temp": 100.0})

    assert rows_of(path)[0][3] == "72.5"


def test_a_batched_reply_yields_a_row_for_each_of_its_readings(tmp_path):
    """Ten records in one frame is the instrument reporting ten times."""
    from lan_sniffer.writers.csv_writer import SessionCSVWriter

    path = tmp_path / "s.csv"
    with SessionCSVWriter(path, ["temp", "o2"], follow="temp") as w:
        w.add(0.0, {"o2": 72.0})
        for i in range(10):
            w.add(i * 0.1, {"temp": 100.0 + i})

    assert len(rows_of(path)) == 10
