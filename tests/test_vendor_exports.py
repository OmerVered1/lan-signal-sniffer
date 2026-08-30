"""Reading the files instrument software writes, onto the capture's clock.

These exports are the ground truth every identification is checked against, so
misreading one is the mistake that cannot be caught later: it produces a
confident fit to nothing. Two ways of misreading them are covered here because
both actually happened.

The first is a column shift. Calisto's header separates most names with two or
more spaces but `Index Time(s)` with exactly one, so splitting on runs of
whitespace merges that pair and moves every column along by one. Nothing fails
— each reading is simply labelled with its neighbour's name.

The second is the clock. Both vendors stamp in local time and a session is
stamped in UTC. A wrong shift does not fail either; it pairs every reading with
the wrong row, or with no row at all, and reports that nothing matched.
"""

from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path

import pytest

from lan_sniffer.analysis.vendor import (
    constant_columns,
    load_calisto,
    load_questor,
    local_offset_hours,
)
from lan_sniffer.writers.merge import export_format, load_export, session_clock_offset

CALISTO = """CeNi3% 850C ArH2 test
Creation Date : 30/08/2026 12:51:51
User : admin
Zone Start Time : 27/08/2026 22:04:09

HeatFlow :
 Initial Mass : 83.9 mg

Index Time(s)     Furnace Temperature(°C) Sample Temperature(°C) HeatFlow(µV) Time(s)     18(A)      2(A)
1     0           22.730051               25.557554              20287.716797 0           3.028935E-6 5.411643E-5
2     3.3         22.733751               25.554356              20287.716797 3.3         3.035331E-6 5.411600E-5
3     6.6         22.726938               25.546938              20287.716797 6.6         3.031921E-6 5.411605E-5
"""

QUESTOR = (
    "Sourcefile\tFile Name.qmp\n"
    "Exporttime\t08.30.2026 12:47:48\n"
    "\n"
    "Start Time\t08/27/26 22:04:10.793000\n"
    "End Time\t08/28/26 14:44:46.913000\n"
    "\n"
    "\t\t18\t\t\t2\n"
    "Time\tTime Relative [s]\tIon Current [A]\tTime\tTime Relative [s]\tIon Current [A]\n"
    "2026-08-27 22:04:10.793000\t0.0\t3.02893448e-06\t"
    "2026-08-27 22:04:10.793000\t0.0\t5.411643219e-05\n"
    "2026-08-27 22:04:18.810000\t8.017\t3.03533101e-06\t"
    "2026-08-27 22:04:18.810000\t8.017\t5.411600876e-05\n"
)


@pytest.fixture
def calisto(tmp_path) -> Path:
    path = tmp_path / "calisto exp.csv"
    path.write_bytes(CALISTO.encode("utf-16"))
    return path


@pytest.fixture
def questor(tmp_path) -> Path:
    # No extension, exactly as the software writes it.
    path = tmp_path / "mass exp"
    path.write_text(QUESTOR, encoding="utf-8")
    return path


# ----- Calisto ---------------------------------------------------------------


def test_calisto_columns_are_not_shifted_by_the_single_space_in_the_header():
    """`Index Time(s)` is two names one space apart; merging them moves all."""
    columns, rows = load_calisto_from(CALISTO)
    assert "Furnace Temperature(°C)" in columns
    assert rows[0][1]["Furnace Temperature(°C)"] == "22.730051"
    assert rows[0][1]["Sample Temperature(°C)"] == "25.557554"
    assert rows[0][1]["18(A)"] == "3.028935E-6"


def load_calisto_from(text: str, tz: float = 0.0):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "c.csv"
        path.write_bytes(text.encode("utf-16"))
        return load_calisto(path, tz)


def test_calisto_elapsed_times_are_placed_by_the_header_start(calisto):
    """The table has no absolute time in it; the header alone supplies it."""
    _columns, rows = load_calisto(calisto, 0.0)
    assert rows[0][0] == datetime(2026, 8, 27, 22, 4, 9)
    assert rows[1][0] == datetime(2026, 8, 27, 22, 4, 12, 300000)


def test_a_calisto_export_without_its_header_start_is_refused(tmp_path):
    """Placing it at an assumed zero would put the run on the wrong day."""
    stripped = "\n".join(
        l for l in CALISTO.splitlines() if "Zone Start Time" not in l
    )
    path = tmp_path / "c.csv"
    path.write_bytes(stripped.encode("utf-16"))
    with pytest.raises(ValueError, match="Zone Start Time"):
        load_calisto(path, 0.0)


def test_a_miscounted_header_is_an_error_not_a_silent_relabel(tmp_path):
    broken = CALISTO.replace("HeatFlow(µV) Time(s)", "HeatFlow(µV)")
    path = tmp_path / "c.csv"
    path.write_bytes(broken.encode("utf-16"))
    with pytest.raises(ValueError, match="would not line up"):
        load_calisto(path, 0.0)


def test_the_clock_column_is_not_offered_as_a_measurement(calisto):
    """A clock correlates with everything that ramps, and reads as a match."""
    columns, _rows = load_calisto(calisto, 0.0)
    assert not any("Time" in c for c in columns), columns


def test_a_column_that_never_moved_is_reported_as_such(calisto):
    columns, rows = load_calisto(calisto, 0.0)
    assert "HeatFlow(µV)" in constant_columns(rows, columns)
    assert "Furnace Temperature(°C)" not in constant_columns(rows, columns)


# ----- Questor ---------------------------------------------------------------


def test_questor_species_are_read_from_the_row_above_the_columns(questor):
    columns, rows = load_questor(questor, 0.0)
    assert columns == ["18", "2"]
    assert rows[0][1]["18"] == "3.02893448e-06"
    assert rows[0][1]["2"] == "5.411643219e-05"
    assert rows[0][0] == datetime(2026, 8, 27, 22, 4, 10, 793000)


def test_a_questor_export_shifts_onto_the_capture_clock(questor):
    _columns, rows = load_questor(questor, 3.0)
    assert rows[0][0] == datetime(2026, 8, 27, 19, 4, 10, 793000)


# ----- recognising them ------------------------------------------------------


def test_each_export_is_recognised_by_its_contents_not_its_name(calisto, questor):
    """Neither file has a reliable extension; the Questor one has none at all."""
    assert export_format(questor) == "questor"
    assert export_format(calisto) == "calisto"


def test_merge_reads_both_through_the_ordinary_entry_point(calisto, questor):
    for path, expected in ((calisto, "18(A)"), (questor, "18")):
        columns, rows = load_export(path, 3.0)
        assert expected in columns
        assert rows


# ----- the clock -------------------------------------------------------------


def test_the_offset_comes_from_the_session_rather_than_a_guess():
    """The name is local, the first record is UTC; the gap is the offset."""
    assert local_offset_hours("dev_20260827_142542", 1787829941.803604) == 3.0


def test_a_session_with_no_rows_still_yields_its_offset(tmp_path):
    """A capture recorded with no profile has a sidecar and an empty CSV."""
    session = tmp_path / "device_1_20260827_142542.csv"
    session.write_text("timestamp_utc,elapsed_s\n", encoding="utf-8")
    sidecar = tmp_path / "device_1_20260827_142542.raw.jsonl"
    sidecar.write_text(
        '{"format": "lan-sniffer-raw", "version": 1}\n'
        '{"ts": 1787829941.803604, "dir": "c2s", "peer": "10.0.0.5:1",'
        ' "dport": 1210, "off": 0, "data": "00"}\n',
        encoding="utf-8",
    )
    assert session_clock_offset(session) == 3.0


def test_an_unnameable_session_offset_is_reported_as_unknown(tmp_path):
    session = tmp_path / "no_timestamp_here.csv"
    session.write_text("timestamp_utc,elapsed_s\n", encoding="utf-8")
    assert session_clock_offset(session) is None
