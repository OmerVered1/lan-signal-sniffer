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


# ----- polling ---------------------------------------------------------------


class FakeTransport:
    """Answers with canned responses, so the client can be driven offline."""

    name = "fake"

    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    def post(self, url, body, timeout_s):
        self.sent.append((url, body))
        if not self.responses:
            return REAL
        got = self.responses.pop(0)
        if isinstance(got, Exception):
            raise got
        return got


def response_with(stamps):
    """A response carrying result sets at the given timestamps."""
    one = REAL[REAL.index(b"<ResultSet>") : REAL.index(b"</ResultSet>") + len(b"</ResultSet>")]
    body = b"".join(
        one.replace(b"2026-08-31T13:14:35.527", s.encode()) for s in stamps
    )
    return REAL[: REAL.index(b"<ResultSet>")] + body + REAL[REAL.index(b"</Lazarus:GetResultsetsResponse>"):]


HISTORY = "2026-08-31T13:19:00.000"


def client_with(responses, prime=True):
    """A client, optionally past its first reply.

    The first reply is always history - whatever the instrument already had
    before anyone asked - so a client that has not made it is not in the state
    the app runs in. Tests that care about live readings prime first.
    """
    from lan_sniffer.readers.questor import QuestorClient

    c = QuestorClient()
    if prime:
        responses = [response_with([HISTORY])] + list(responses)
    c.transport = FakeTransport(responses)
    if prime:
        assert c.poll() == [], "the first reply is history and belongs to nobody"
    return c


def test_the_first_reply_is_history_and_is_not_recorded():
    """It reaches back before the app was watching.

    Those are real measurements, but not part of this recording - and keeping
    them put readings from twenty seconds before a session inside it, with a
    negative elapsed time.
    """
    c = client_with([], prime=False)
    c.transport = FakeTransport([
        response_with([
            "2026-08-31T13:18:51.637",
            "2026-08-31T13:18:59.526",
            "2026-08-31T13:19:07.339",
        ]),
        response_with([
            "2026-08-31T13:18:59.526",
            "2026-08-31T13:19:07.339",
            "2026-08-31T13:19:15.122",
        ]),
    ])
    assert c.poll() == []
    assert [r.when.strftime("%H:%M:%S") for r in c.poll()] == ["13:19:15"]


def test_a_result_is_returned_once_and_not_again():
    """The server keeps a short history, so every poll repeats what it just gave."""
    c = client_with([response_with(["2026-08-31T13:19:51.147"])] * 3)
    assert len(c.poll()) == 1
    assert c.poll() == []
    assert c.poll() == []


def test_results_that_appeared_between_polls_are_all_picked_up():
    """Asking for several is what stops a late poll losing the ones in between."""
    c = client_with([
        response_with(["2026-08-31T13:19:51.147"]),
        response_with([
            "2026-08-31T13:19:51.147",
            "2026-08-31T13:19:59.017",
            "2026-08-31T13:20:06.857",
        ]),
    ])
    assert len(c.poll()) == 1
    fresh = c.poll()
    assert len(fresh) == 2
    assert [r.when.strftime("%H:%M:%S") for r in fresh] == ["13:19:59", "13:20:06"]


def test_results_come_back_oldest_first():
    c = client_with([response_with([
        "2026-08-31T13:20:06.857",
        "2026-08-31T13:19:51.147",
        "2026-08-31T13:19:59.017",
    ])])
    got = [r.when.strftime("%H:%M:%S") for r in c.poll()]
    assert got == sorted(got)


def test_a_failed_poll_reports_itself_and_does_not_lose_the_history():
    c = client_with([
        response_with(["2026-08-31T13:19:51.147"]),
        RuntimeError("HTTP 401 Unauthorized"),
        response_with(["2026-08-31T13:19:51.147", "2026-08-31T13:19:59.017"]),
    ])
    assert len(c.poll()) == 1
    assert c.poll() == []
    assert "401" in c.last_error
    fresh = c.poll()
    assert len(fresh) == 1, "the already-seen result must not come back"
    assert c.last_error == ""


def test_the_same_instant_on_two_valves_is_two_measurements():
    later = REAL.replace(b"2026-08-31T13:14:35.527", b"2026-08-31T13:19:51.147")
    one = later[later.index(b"<ResultSet>") : later.index(b"</ResultSet>") + 12]
    two = later[: later.index(b"<ResultSet>")] + one + one.replace(
        b"<ValveId>1</ValveId>", b"<ValveId>2</ValveId>"
    ) + later[later.index(b"</Lazarus:GetResultsetsResponse>"):]
    c = client_with([two])
    got = c.poll()
    assert len(got) == 2, "the same instant on two valves is two measurements"


def test_the_url_is_built_the_way_the_browser_addresses_it():
    from lan_sniffer.readers.questor import QuestorClient

    assert QuestorClient().url == "http://localhost/questor5/Soap/ResultServer.asp"
    assert QuestorClient(host="ms-pc", port=8080).url.startswith("http://ms-pc:8080/")


# ----- as a device in a session ----------------------------------------------


def monitor_reading(responses):
    """A monitor past its priming poll, as start_capture leaves it."""
    from lan_sniffer.monitor import DeviceConfig, DeviceMonitor
    from lan_sniffer.readers.questor import QuestorClient

    m = DeviceMonitor(config=DeviceConfig(label="ms", questor_host="localhost"))
    m.questor = QuestorClient()
    m.questor.transport = FakeTransport(
        [response_with([HISTORY])] + list(responses)
    )
    # start_capture asks once to learn the tag names, and drops the readings:
    # nothing is recording yet, and that reply is history.
    for entry in m.questor.poll():
        pass
    m._next_questor = 0.0
    return m


def test_a_questor_device_produces_samples_for_a_session():
    m = monitor_reading([response_with(["2026-08-31T13:19:51.147"])])
    got = m.poll()
    assert len(got.samples) == 1
    # Unprefixed: a lone device keeps its own column names, as everywhere else.
    assert got.samples[0].values["V1_C_O2"] == pytest.approx(73.241630554199)


def test_its_columns_are_prefixed_when_it_shares_a_file():
    """Two instruments in one session have to be told apart."""
    m = monitor_reading([response_with(["2026-08-31T13:19:51.147"])])
    m.prefix = "ms."
    got = m.poll()
    assert "ms.V1_C_O2" in got.samples[0].values
    assert "ms.V1_C_O2" in m.signal_names()


def test_its_columns_and_units_come_from_what_it_answered():
    m = monitor_reading([response_with(["2026-08-31T13:19:51.147"])])
    assert m.signal_names() == [], "nothing is known before the first reply"
    m.poll()
    names = m.signal_names()
    assert "V1_I_18" in names and "V1_C_H2" in names
    assert m.units()["V1_C_H2"] == "%"
    # The intensity tags carry no unit, and one must not be invented.
    assert m.units()["V1_I_18"] == ""


def test_it_is_not_asked_faster_than_it_answers():
    """Results appear every eight seconds; polling flat out would be rude."""
    m = monitor_reading([response_with(["2026-08-31T13:19:51.147"])] * 5)
    m.config.questor_interval_s = 60.0
    assert len(m.poll().samples) == 1
    assert m.poll().samples == []
    # One priming request at start-up, then one poll. The rate gate stops the
    # rest.
    assert len(m.questor.transport.sent) == 2


def test_a_questor_device_never_drives_a_session():
    """It has no notion of a run - it is always acquiring."""
    from lan_sniffer.monitor import DeviceConfig, DeviceMonitor

    m = DeviceMonitor(config=DeviceConfig(label="ms", questor_host="localhost"))
    assert m.reads_questor
    assert m.detector is None, "no profile, so nothing can open or close a file"


# ----- what belongs in this recording ----------------------------------------


def test_a_reset_makes_the_next_reply_the_new_history():
    c = client_with([response_with(["2026-08-31T13:19:22.809"])] * 3)
    assert len(c.poll()) == 1
    c.reset()
    assert c.poll() == [], "after a reset the next reply is history again"
