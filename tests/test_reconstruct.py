"""Finding a vendor's published values inside captured traffic.

Correlation rather than value matching. A reading held in counts, or scaled by
some factor the vendor software applies before display, never equals the
published number but tracks it exactly — and a search that demands equality
walks straight past it.

Every fit is judged on a stretch of the run it was not fitted on, because a
scale and offset can be made to match almost anything over the window used to
choose them.
"""

from __future__ import annotations

import math
import struct
from datetime import datetime, timedelta

import pytest
import synth

from lan_sniffer.analysis.reconstruct import (
    analyse,
    build_array_channels,
    channels_from_chunks,
    find_bands,
    find_scalars,
)

BASE = 1_700_000_000.0


def composition(seconds: float) -> float:
    """A species desorbing: flat, a peak, then flat again.

    A function of elapsed time, not of sample number. The two sides sample at
    different rates, and indexing by sample would put them on different time
    bases — which is exactly the mistake correlation is meant to catch.
    """
    return 0.05 + 2.4 * math.exp(-((seconds - 90.0) ** 2) / 700.0)


def vendor_export(n=200, step=1.0, column="V1_I_18"):
    """What the instrument's own software logged, as merge.load_export returns."""
    return [
        (
            datetime.utcfromtimestamp(BASE + i * step),
            {column: f"{composition(i * step):.6f}"},
        )
        for i in range(n)
    ]


def capture_with_scalar(n=200, scale=1e5, offset=8):
    """A device that sends the value in counts, not in the published unit."""
    request = bytes.fromhex("52000000")
    exchanges = []
    for i in range(n):
        reply = bytearray(b"\x00" * 24)
        struct.pack_into("<I", reply, 4, 900_000 + i * 37)          # a clock
        struct.pack_into("<f", reply, offset, composition(i) * scale)  # counts, 1 Hz
        exchanges.append((BASE + i, request, BASE + i + 0.01, bytes(reply)))
    return synth.build_capture(exchanges, device_port=30000)


def capture_with_array(n=120, band=(1436, 1440), width=2048):
    """A device that sends a spectrum, with one band tracking the species."""
    request = bytes.fromhex("53000000")
    exchanges = []
    for i in range(n):
        when = i * 2.0  # the analyser sweeps every two seconds
        values = [8800 + ((i * 7 + j * 13) % 40) for j in range(width)]  # baseline
        for j in range(band[0], band[1] + 1):
            values[j] = int(8800 + composition(when) * 900)
        body = b"".join(struct.pack("<I", v << 8) for v in values)
        reply = struct.pack("<II", 5, width) + body
        exchanges.append((BASE + when, request, BASE + when + 0.01, reply))
    return synth.build_capture(exchanges, device_port=30000)


# ----- a value hiding in a plain field --------------------------------------


def test_a_value_sent_in_counts_is_found_by_correlation():
    """It never equals the published number, so equality would miss it."""
    replies = channels_from_chunks(capture_with_scalar())
    fits = find_scalars(replies, vendor_export(), ["V1_I_18"])
    assert fits, "correlation should find a field that tracks the reading"
    best = fits[0]
    assert best.byte_offset == 8
    assert best.convincing, f"held-out r was only {best.r_holdout:.3f}"


def test_the_fit_recovers_the_scale_the_software_applies():
    fits = find_scalars(
        channels_from_chunks(capture_with_scalar(scale=1e5)),
        vendor_export(),
        ["V1_I_18"],
    )
    assert fits[0].scale == pytest.approx(1e-5, rel=0.02)


def test_a_clock_in_the_same_reply_is_not_mistaken_for_the_value():
    fits = find_scalars(
        channels_from_chunks(capture_with_scalar()), vendor_export(), ["V1_I_18"]
    )
    assert fits[0].byte_offset != 4, "byte 4 is the tick counter"


def test_nothing_is_claimed_when_the_traffic_does_not_carry_it():
    """A capture with no relationship must produce no convincing fit."""
    request = bytes.fromhex("52000000")
    exchanges = []
    for i in range(200):
        reply = bytearray(b"\x00" * 24)
        struct.pack_into("<I", reply, 4, 900_000 + i * 37)
        exchanges.append((BASE + i, request, BASE + i + 0.01, bytes(reply)))
    replies = channels_from_chunks(synth.build_capture(exchanges, device_port=30000))
    fits = find_scalars(replies, vendor_export(), ["V1_I_18"])
    assert not any(f.convincing for f in fits)


# ----- a value hiding in an array -------------------------------------------


def test_the_array_band_that_tracks_the_reading_is_located():
    arrays = build_array_channels(channels_from_chunks(capture_with_array()))
    assert arrays, "the large replies should be read as arrays"
    fits = find_bands(arrays, vendor_export(n=240, step=1.0), ["V1_I_18"])
    assert fits, "a band should be proposed"
    best = fits[0]
    assert best.start <= 1438 <= best.end, f"found {best.start}..{best.end}"
    assert best.convincing, f"held-out r was only {best.r_holdout:.3f}"


def test_a_band_is_grown_rather_than_reported_as_a_single_index():
    fits = find_bands(
        build_array_channels(channels_from_chunks(capture_with_array())),
        vendor_export(n=240),
        ["V1_I_18"],
    )
    assert fits[0].end > fits[0].start, "a peak spans several indices"


# ----- the report ------------------------------------------------------------


def test_the_report_names_what_it_solved():
    report = analyse(capture_with_scalar(), vendor_export(), ["V1_I_18"])
    assert report.solved == ["V1_I_18"]


def test_a_column_that_never_moves_is_called_out():
    """Correlation cannot identify a channel that holds still."""
    flat = [
        (datetime.utcfromtimestamp(BASE + i), {"V1_I_4": "115.6"}) for i in range(200)
    ]
    report = analyse(capture_with_scalar(), flat, ["V1_I_4"])
    assert any("less than 10%" in n for n in report.notes)
    assert report.solved == []


def test_an_empty_capture_says_so():
    report = analyse([], vendor_export(), ["V1_I_18"])
    assert report.solved == []
    assert report.notes


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))


# ----- limits that hid the answer last time ---------------------------------


def capture_with_deep_scalar(n=200, at=1500, size=3000):
    """A large reply that carries the value well past its first kilobyte."""
    request = bytes.fromhex("54000000")
    exchanges = []
    for i in range(n):
        reply = bytearray(bytes(range(256)) * (size // 256 + 1))[:size]
        struct.pack_into("<f", reply, at, composition(i) * 1e5)
        exchanges.append((BASE + i, request, BASE + i + 0.01, bytes(reply)))
    return synth.build_capture(exchanges, device_port=30000)


def test_a_value_deep_inside_a_large_reply_is_still_found():
    """The previous search stopped at a kilobyte and concluded 'not sent'."""
    replies = channels_from_chunks(capture_with_deep_scalar())
    fits = find_scalars(replies, vendor_export(), ["V1_I_18"])
    assert fits, "a field at byte 1500 must be within reach of the sweep"
    assert fits[0].byte_offset == 1500
    assert fits[0].convincing


def test_the_report_says_how_deep_the_sweep_actually_went():
    """A limit that goes unmentioned is how a wrong conclusion gets believed."""
    report = analyse(
        capture_with_deep_scalar(size=3000), vendor_export(), ["V1_I_18"]
    )
    assert any("3000 bytes" in note and "2048" in note for note in report.notes), (
        f"expected the truncation to be reported, got {report.notes}"
    )


def test_a_text_column_in_the_export_does_not_stop_the_search():
    """Vendor exports carry status text beside the numbers."""
    numeric = vendor_export()
    vendor = [
        (ts, {**row, "V1_Status": "Scanning"}) for ts, row in numeric
    ]
    report = analyse(
        capture_with_scalar(), vendor, ["V1_I_18", "V1_Status"]
    )
    assert "V1_I_18" in report.solved


# ----- working from what the user actually kept ------------------------------


def test_the_search_works_from_a_survey_csv_too():
    """Record everything writes three files; the .raw.jsonl is the forgotten one."""
    from lan_sniffer.analysis.reconstruct import channels_from_survey
    from lan_sniffer.writers.survey import build_survey, write_survey

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "survey.csv"
        write_survey(build_survey(capture_with_scalar()), csv_path)
        replies = channels_from_survey(csv_path)

    assert replies, "the CSV's hex columns should rebuild the channels"
    fits = find_scalars(replies, vendor_export(), ["V1_I_18"])
    assert fits and fits[0].byte_offset == 8
    assert fits[0].convincing, "the CSV route must reach the same answer"


def test_a_capture_too_short_to_settle_the_question_says_so():
    """An empty result from eighteen seconds is not evidence of absence."""
    report = analyse(capture_with_scalar(n=25), vendor_export(n=25), ["V1_I_18"])
    assert any("covers only" in note for note in report.notes), report.notes


def test_two_instruments_in_one_capture_keep_their_channels_apart():
    """Channel numbering restarts per flow, so ch0 exists on both."""
    from lan_sniffer.capture.reassembly import TCPReassembler

    chunks = []
    for name, ip, port in (("ov", "169.254.60.1", 1210), ("ms", "172.16.0.1", 30000)):
        asm = TCPReassembler(ip)
        c_seq = s_seq = 1000
        for i in range(30):
            req = b"\x52\x00\x00\x00"
            chunks += asm.add_segment(BASE + i, "10.0.0.5", 51234, ip, port, c_seq, req)
            c_seq += len(req)
            reply = name.encode() * 12
            chunks += asm.add_segment(
                BASE + i + 0.01, ip, port, "10.0.0.5", 51234, s_seq, reply
            )
            s_seq += len(reply)

    replies = channels_from_chunks(chunks)
    assert len(replies) == 2, f"expected one channel per device, got {list(replies)}"
    for key, samples in replies.items():
        bodies = {p for _t, p in samples}
        assert len(bodies) == 1, f"{key} mixed two instruments' replies together"
