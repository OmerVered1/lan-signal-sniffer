"""Joining a vendor export onto a recorded session.

Some instruments never transmit the numbers their software publishes. A process
mass spectrometer streams raw detector arrays and the concentrations are
computed in the vendor software, so sniffing recovers arrays and not values.
Where the two clocks agree the files can be joined on time instead, which
produces the same combined table for an instrument that cannot be decoded.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from lan_sniffer.writers.merge import (
    load_export,
    merge_into_session,
    parse_timestamp,
)


def write(path: Path, text: str, encoding: str = "utf-8") -> Path:
    path.write_text(text, encoding=encoding)
    return path


def a_session(tmp_path, rows=6, start=0):
    lines = ["timestamp_utc,elapsed_s,oven.sample_temperature (degC)"]
    for i in range(rows):
        lines.append(
            "2026-08-25 16:53:%02d.000,%d.000,%.3f" % (54 + start + i, i, 25.0 + i)
        )
    return write(tmp_path / "session.csv", "\n".join(lines) + "\n")


def a_questor_export(tmp_path, step=8, rows=6):
    from datetime import datetime, timedelta

    base = datetime(2026, 8, 25, 16, 53, 54, 903000)
    lines = ["Timestamp,V1_I_18,V1_I_4"]
    for i in range(rows):
        when = base + timedelta(seconds=i * step)
        lines.append(
            "%s,%.6f,%.6f"
            % (when.strftime("%m/%d/%y %H:%M:%S.%f")[:-3], 0.49 + i * 0.01, 115.6)
        )
    return write(tmp_path / "questor.csv", "\n".join(lines) + "\n")


# ----- reading a vendor export ----------------------------------------------


def test_the_questor_timestamp_format_is_understood():
    assert parse_timestamp("08/25/26 14:50:11.903") is not None
    assert parse_timestamp("2026-08-25 16:53:54.071") is not None
    assert parse_timestamp("not a time") is None


def test_a_prose_preamble_is_skipped(tmp_path):
    """A vendor export often puts several lines of headings before the table."""
    path = write(
        tmp_path / "vendor.txt",
        "testing signal recognition\n"
        "Creation Date: 09/08/2026 10:58:39\n"
        "User: admin\n"
        "\n"
        "Timestamp\tSample Temperature\n"
        "08/25/26 16:53:54.000\t25.629\n"
        "08/25/26 16:53:55.000\t25.630\n",
    )
    columns, samples = load_export(path)
    assert columns == ["Sample Temperature"]
    assert len(samples) == 2


def test_an_export_with_only_elapsed_seconds_is_refused(tmp_path):
    """Calisto's own export has no clock in the table, only Time(s).

    Merging joins on absolute time, so a file that never states one cannot be
    used — and treating a row index as a timestamp would line the two sources
    up at 1970 and quietly match nothing.
    """
    path = write(
        tmp_path / "elapsed.txt",
        "Index\tTime(s)\tSample Temperature\n1\t0\t25.629\n2\t1\t25.630\n",
    )
    with pytest.raises(ValueError, match="timestamp"):
        load_export(path)


def test_a_utf16_export_is_read(tmp_path):
    path = tmp_path / "utf16.csv"
    path.write_text("Timestamp,value\n08/25/26 16:53:54.000,1.5\n", encoding="utf-16")
    columns, samples = load_export(path)
    assert columns == ["value"] and len(samples) == 1


def test_a_tab_separated_export_is_read(tmp_path):
    path = write(tmp_path / "tabs.tsv", "Timestamp\tvalue\n08/25/26 16:53:54.000\t2.5\n")
    columns, samples = load_export(path)
    assert columns == ["value"] and samples[0][1]["value"] == "2.5"


def test_an_empty_export_is_refused(tmp_path):
    with pytest.raises(ValueError, match="empty"):
        load_export(write(tmp_path / "nothing.csv", ""))


# ----- the merge itself ------------------------------------------------------


def test_the_export_columns_are_added_to_every_row(tmp_path):
    result = merge_into_session(
        a_session(tmp_path), a_questor_export(tmp_path), tmp_path / "out.csv"
    )
    rows = list(csv.reader((tmp_path / "out.csv").open()))
    assert rows[0] == [
        "timestamp_utc", "elapsed_s", "oven.sample_temperature (degC)",
        "V1_I_18", "V1_I_4",
    ]
    assert len(rows) - 1 == result.rows == 6


def test_each_row_takes_the_nearest_reading_in_time(tmp_path):
    merge_into_session(
        a_session(tmp_path), a_questor_export(tmp_path, step=8), tmp_path / "out.csv"
    )
    rows = list(csv.reader((tmp_path / "out.csv").open()))[1:]
    # The analyser reports every 8 s; a session second-by-second holds the same
    # reading until the next one arrives.
    assert rows[0][3] == rows[1][3], "no reading exists between two samples"
    assert rows[0][3] != rows[5][3], "but a later row must take a later reading"


def test_readings_are_not_invented_between_samples(tmp_path):
    """Interpolating would put numbers in the file no instrument reported."""
    merge_into_session(
        a_session(tmp_path), a_questor_export(tmp_path, step=8), tmp_path / "out.csv"
    )
    values = {r[3] for r in list(csv.reader((tmp_path / "out.csv").open()))[1:]}
    source = {"%.6f" % (0.49 + i * 0.01) for i in range(6)}
    assert values <= source, "every value must be one the export actually contains"


def test_rows_beyond_the_export_are_left_blank(tmp_path):
    # The oven ran on after the analyser stopped; those rows have no reading.
    session = a_session(tmp_path, rows=6, start=600)
    result = merge_into_session(
        session, a_questor_export(tmp_path), tmp_path / "out.csv", tolerance_s=30
    )
    rows = list(csv.reader((tmp_path / "out.csv").open()))[1:]
    assert all(r[3] == "" for r in rows)
    assert result.matched == 0
    assert result.warnings, "a merge that matched nothing must say so"


def test_a_clock_offset_can_be_corrected(tmp_path):
    session = a_session(tmp_path)
    # The same readings, stamped in local time three hours ahead.
    lines = ["Timestamp,V1_I_4"]
    for i in range(6):
        lines.append("08/25/26 19:53:%02d.903,115.6" % (54 + i))
    export = write(tmp_path / "local.csv", "\n".join(lines) + "\n")

    naive = merge_into_session(session, export, tmp_path / "a.csv")
    assert naive.matched == 0, "three hours out, nothing should match"

    fixed = merge_into_session(
        session, export, tmp_path / "b.csv", tz_offset_hours=3
    )
    assert fixed.matched == fixed.rows


def test_colliding_column_names_are_refused(tmp_path):
    session = write(
        tmp_path / "s.csv",
        "timestamp_utc,elapsed_s,V1_I_4\n2026-08-25 16:53:54.000,0,1\n",
    )
    with pytest.raises(ValueError, match="already exist"):
        merge_into_session(session, a_questor_export(tmp_path), tmp_path / "out.csv")


def test_a_prefix_keeps_the_two_sources_apart(tmp_path):
    merge_into_session(
        a_session(tmp_path),
        a_questor_export(tmp_path),
        tmp_path / "out.csv",
        prefix="ms.",
    )
    header = list(csv.reader((tmp_path / "out.csv").open()))[0]
    assert "ms.V1_I_4" in header


def test_the_session_is_never_modified(tmp_path):
    session = a_session(tmp_path)
    before = session.read_text()
    merge_into_session(session, a_questor_export(tmp_path), tmp_path / "out.csv")
    assert session.read_text() == before


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
