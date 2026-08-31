"""Reading Questor5's own results over the interface its own UI uses.

The fixture here is a real response from the instrument, captured on
2026-08-31, not something written to match the parser. That matters: this whole
route exists because two searches of the analyser's own traffic proved the
published values are computed in software and never put on that link, so the
one thing that must not happen is a parser that agrees with an idea of the
format rather than with the instrument.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from lan_sniffer.readers.questor import (
    build_request,
    parse_results,
    parse_timestamp,
)

REAL = (Path(__file__).parent / "fixtures" / "questor_results.xml").read_bytes()


def test_the_real_response_yields_every_tag():
    results = parse_results(REAL)
    assert len(results) == 1
    got = results[0]
    assert len(got.values) == 15, sorted(got.values)
    assert got.values["V1_I_18"] == pytest.approx(7.271817207336)
    assert got.values["V1_C_O2"] == pytest.approx(73.241630554199)
    assert got.values["V1_I_14"] == pytest.approx(-0.152603626251)


def test_the_timestamp_is_read_because_nothing_lines_up_without_it():
    got = parse_results(REAL)[0]
    assert got.when == datetime(2026, 8, 31, 13, 14, 35, 527000)
    assert got.valve == "1"


def test_units_come_from_the_instrument_not_from_a_guess():
    got = parse_results(REAL)[0]
    assert got.units["V1_C_O2"] == "%"
    # The intensity tags carry an empty unit attribute; inventing one would
    # assert a scale nobody has established.
    assert "V1_I_18" not in got.units


def test_a_result_set_without_a_time_is_dropped_not_guessed():
    """A value with no moment cannot be lined up against another instrument."""
    broken = REAL.replace(b"<TimeStamp>2026-08-31T13:14:35.527</TimeStamp>", b"")
    assert parse_results(broken) == []


def test_a_soap_fault_is_raised_not_returned_as_no_data():
    """Empty means the instrument had nothing new; a refusal is not that."""
    fault = (
        b'<?xml version="1.0"?><SOAP-ENV:Envelope '
        b'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>-1</faultcode>"
        b"<faultstring>getresults() Function Not IMPLEMENTED</faultstring>"
        b"</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
    with pytest.raises(ValueError, match="Not IMPLEMENTED"):
        parse_results(fault)


def test_rubbish_is_reported_rather_than_parsed():
    with pytest.raises(ValueError, match="not XML"):
        parse_results(b"<html>401 Unauthorized")


def test_the_request_calls_the_function_the_dispatcher_will_find():
    """SoapCommon.inc strips 'Lazarus:' and lower-cases the rest."""
    body = build_request(count=3).decode()
    assert "<Lazarus:GetResults>" in body
    assert "<Count>3</Count>" in body
    assert 'xmlns:Lazarus="http://us.abb.com/extrel/Lazarus/"' in body


def test_timestamps_with_and_without_fractional_seconds():
    assert parse_timestamp("2026-08-31T13:14:35.527") is not None
    assert parse_timestamp("2026-08-31T13:14:35") is not None
    assert parse_timestamp("not a time") is None
