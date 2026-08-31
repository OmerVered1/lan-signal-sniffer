"""The window must act on what the detector tells it.

These exist because of a shipped bug that every unit test passed straight over.
The detector correctly returned "stop" when the instrument sent its end-of-run
command, and the window discarded the value — it acted only on "start". Since
the quiet timeout is deliberately withheld whenever a stop command exists,
nothing else could close the session, so a recording ran on for ever after the
experiment finished.

Both halves were individually correct and individually tested. The fault was in
the wiring between them, which is only reachable by driving the window itself,
so that is what these do rather than calling the detector directly.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
import synth

pytest.importorskip("PyQt5.QtWidgets")

from lan_sniffer.capture.reassembly import TCPReassembler  # noqa: E402

PROFILE_DIR = Path(__file__).resolve().parents[1] / "profiles"

START_CMD = bytes.fromhex("00040001000005")
STOP_CMD = bytes.fromhex("00040001000002")
STATUS_REQ = bytes.fromhex("0008")
IDLE_REQ = bytes.fromhex("000100020004")


@pytest.fixture(scope="module")
def qapp():
    from PyQt5.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


class FakePump:
    """Stands in for a capture so the window's own loop can be driven.

    Injecting chunks here rather than calling the decoder directly means the
    tests cross every seam the real thing does — poll, event handling, session
    open and close — which is where the faults that reached the bench lived.
    """

    def __init__(self) -> None:
        self.queued = []

    def poll(self, limit: int = 5000):
        out, self.queued = self.queued, []
        return out

    def status(self) -> str:
        return "fake"

    def stop(self) -> None:
        pass


def configure(window, index, label, ip, profile="Setaram DSC (Setline)"):
    """Fill in one device's panel the way a user would."""
    form = window._device_forms[index]
    assert form.select_profile(profile), f"{profile} must be loadable"
    form.set_label(label)
    form.set_address(ip)
    form._emit_changed()
    form.save()
    return form


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from lan_sniffer.ui import main_window as mw

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    w._output_dir = tmp_path / "sessions"
    configure(w, 0, "dsc", "169.254.93.1")
    arm(w)
    yield w
    w.close()


def arm(window):
    """Put the window in the state a running capture would."""
    for monitor in window._monitors:
        if monitor.pump is None:
            monitor.pump = FakePump()
    window._capturing = True


def status_reply(temperature: float, heat_flow: float) -> bytes:
    """A 23-byte packed status frame, the shape the real DSC replies with."""
    body = bytearray(bytes.fromhex("0008000100011b03000110370a0001") + b"\x00" * 8)
    struct.pack_into(">f", body, 15, temperature)
    struct.pack_into(">f", body, 19, heat_flow)
    return bytes(body)


def feed(window, exchanges, device: int = 0) -> None:
    """Replay request/reply pairs into one device, then run the window's loop."""
    arm(window)
    monitor = window._monitors[device]
    asm = TCPReassembler(synth.DEVICE_IP)
    c_seq, s_seq = 1000, 5000
    for ts, request, reply in exchanges:
        chunks = asm.add_segment(
            ts, synth.PEER_IP, 51234, synth.DEVICE_IP, 1210, c_seq, request
        )
        c_seq += len(request)
        if reply:
            chunks += asm.add_segment(
                ts + 0.01, synth.DEVICE_IP, 1210, synth.PEER_IP, 51234, s_seq, reply
            )
            s_seq += len(reply)
        monitor.pump.queued.extend(chunks)
        window._poll()


def a_run(start_at=20.0, stop_at=920.0, until=1000.0):
    """Idle polling throughout, with a run bracketed by its own commands."""
    exchanges = []
    for t in range(0, int(until)):
        exchanges.append((float(t), IDLE_REQ, b"\x00" * 10))
        if t == int(start_at):
            exchanges.append((start_at, START_CMD, b""))
        if start_at <= t <= stop_at:
            exchanges.append((t + 0.2, STATUS_REQ, status_reply(25.0 + t * 0.02, -0.6)))
        if t == int(stop_at):
            exchanges.append((stop_at, STOP_CMD, b""))
    return exchanges


# ----- the seam -------------------------------------------------------------


def test_the_stop_command_actually_closes_the_session(window):
    """The shipped bug, at the level it actually occurred."""
    feed(window, a_run())
    assert window._csv is None, "the run ended; recording must have stopped"
    assert window._session_started is None


def test_the_start_command_opens_a_session(window):
    feed(window, a_run(stop_at=10_000, until=200))
    assert window._csv is not None, "a run is under way; it must be recording"


def test_the_recorded_file_covers_the_run_and_nothing_after(window, tmp_path):
    import csv as csvmod

    feed(window, a_run(start_at=20.0, stop_at=120.0, until=400.0))
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    assert len(written) == 1
    rows = list(csvmod.reader(written[0].open()))[1:]
    assert rows, "the session file must contain the run"
    # Idle polling continues for 280 s after the run; none of it belongs here.
    assert float(rows[-1][1]) < 110, "recording continued past the end of the run"


def test_a_second_run_gets_its_own_file(window, tmp_path):
    feed(window, a_run(start_at=20.0, stop_at=120.0, until=200.0))
    feed(window, a_run(start_at=300.0, stop_at=400.0, until=500.0))
    assert window._csv is None
    assert len(sorted((tmp_path / "sessions").glob("*.csv"))) == 2


def test_idle_polling_alone_records_nothing(window, tmp_path):
    feed(window, [(float(t), IDLE_REQ, b"\x00" * 10) for t in range(300)])
    assert window._csv is None
    assert not sorted((tmp_path / "sessions").glob("*.csv"))


def test_the_banner_follows_the_real_state(window):
    feed(window, a_run(stop_at=10_000, until=200))
    window._update_session_label()
    assert "RECORDING" in window._banner.text()
    assert "NOT" not in window._banner.text()

    feed(window, [(10_000.0, STOP_CMD, b"")])
    window._update_session_label()
    assert "NOT RECORDING" in window._banner.text()


def test_two_sessions_in_the_same_second_do_not_overwrite_each_other(window, tmp_path):
    # Session files are named to the second, and Split here or a quick
    # stop/start can open two inside one. Overwriting the first would destroy a
    # recording silently.
    feed(window, a_run(start_at=1.0, stop_at=2.0, until=3.0))
    feed(window, a_run(start_at=10.0, stop_at=11.0, until=12.0))
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    assert len(written) == 2, f"one file was overwritten: {[p.name for p in written]}"


# ----- two devices, one file ------------------------------------------------


def add_second_device(window, label="dsc2"):
    """Watch a second instrument alongside the first."""
    window._add_device()
    configure(window, 1, label, "169.254.93.2")
    arm(window)


def test_one_device_keeps_its_columns_unprefixed(window, tmp_path):
    # Files recorded before multi-device support must stay comparable.
    feed(window, a_run(start_at=1.0, stop_at=5.0, until=8.0))
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    header = written[0].read_text().splitlines()[0]
    assert "sample_temperature (degC)" in header
    assert "dsc." not in header


def test_two_devices_get_their_names_on_their_columns(window, tmp_path):
    add_second_device(window)
    feed(window, a_run(start_at=1.0, stop_at=5.0, until=8.0), device=0)
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    header = written[0].read_text().splitlines()[0]
    # Both instruments report a signal called sample_temperature; without the
    # prefix one would overwrite the other in the same row.
    assert "dsc.sample_temperature (degC)" in header
    assert "dsc2.sample_temperature (degC)" in header


def feed_together(window, per_device) -> None:
    """Replay several devices at once, in timestamp order.

    Feeding one device's whole run before the other's starts would be two
    sequential experiments, which correctly produce two files. Instruments
    running side by side have to be interleaved to be tested at all.
    """
    arm(window)
    streams = []
    for device, exchanges in per_device:
        asm = TCPReassembler(synth.DEVICE_IP)
        streams.append([device, asm, list(exchanges), 1000, 5000])

    while any(stream[2] for stream in streams):
        streams.sort(key=lambda st: st[2][0][0] if st[2] else float("inf"))
        stream = streams[0]
        device, asm, exchanges, c_seq, s_seq = stream
        ts, request, reply = exchanges.pop(0)
        chunks = asm.add_segment(
            ts, synth.PEER_IP, 51234 + device, synth.DEVICE_IP, 1210, c_seq, request
        )
        stream[3] = c_seq + len(request)
        if reply:
            chunks += asm.add_segment(
                ts + 0.01, synth.DEVICE_IP, 1210,
                synth.PEER_IP, 51234 + device, s_seq, reply,
            )
            stream[4] = s_seq + len(reply)
        window._monitors[device].pump.queued.extend(chunks)
        window._poll()


def test_both_devices_write_into_the_same_file(window, tmp_path):
    import csv as csvmod

    add_second_device(window)
    feed_together(
        window,
        [
            (0, a_run(start_at=1.0, stop_at=200.0, until=210.0)),
            (1, a_run(start_at=2.0, stop_at=200.0, until=210.0)),
        ],
    )
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    assert len(written) == 1, "one session must cover both devices"

    rows = list(csvmod.reader(written[0].open()))
    header, body = rows[0], rows[1:]
    for name in ("dsc.sample_temperature (degC)", "dsc2.sample_temperature (degC)"):
        column = header.index(name)
        assert any(r[column] for r in body), f"{name} was never written"


def test_a_session_opens_as_soon_as_either_device_starts(window):
    add_second_device(window)
    feed(window, [(1.0, START_CMD, b"")], device=1)
    assert window._csv is not None
    assert window._monitors[1].running and not window._monitors[0].running


def test_the_file_stays_open_while_any_device_is_still_running(window):
    """Closing on the first stop would truncate the file mid-experiment."""
    add_second_device(window)
    feed(window, [(1.0, START_CMD, b"")], device=0)
    feed(window, [(2.0, START_CMD, b"")], device=1)
    assert window._csv is not None

    feed(window, [(100.0, STOP_CMD, b"")], device=0)
    assert window._csv is not None, "the second device is still running"

    feed(window, [(200.0, STOP_CMD, b"")], device=1)
    assert window._csv is None, "both have stopped; the file must close"


def test_removing_a_device_drops_its_columns(window):
    add_second_device(window)
    assert any(m.prefix for m in window._monitors)
    window._remove_device(window._monitors[1])
    assert len(window._monitors) == 1
    # Back to one device, so the prefix goes away again.
    assert window._monitors[0].prefix == ""


def test_relabelling_devices_does_not_pile_up_legend_entries(qapp):
    """The plot is rebuilt whenever the device list or a label changes.

    Emptying the curves without taking them off the plot left every previous
    name in the legend, so with two devices a few relabels buried the chart
    under its own key.
    """
    from lan_sniffer.ui.live_view import LiveView

    view = LiveView()
    names = [f"dsc.sig{i}" for i in range(7)] + [f"c80.sig{i}" for i in range(5)]
    for _ in range(4):
        view.set_signals(names, {})
    assert len(view._curves) == len(names)
    assert view._legend_row.count() == len(names)
    assert len(view._boxes) == len(names)


def test_the_plot_drops_signals_that_are_gone(qapp):
    from lan_sniffer.ui.live_view import LiveView

    view = LiveView()
    view.set_signals(["a", "b", "c"], {})
    view.set_signals(["a"], {})
    assert list(view._curves) == ["a"]
    assert view._legend_row.count() == 1


# ----- a coupled rig: one instrument owns the experiment ---------------------


def test_a_passenger_device_never_opens_a_session(window):
    """A TPD rig's run belongs to the oven, not the gas analyser.

    A mass spectrometer polls continuously and has no notion of a run at all,
    so whatever its traffic looks like it must never start or stop the file.
    """
    add_second_device(window, label="ms")
    window._monitors[1].config.controls_recording = False

    feed(window, [(1.0, START_CMD, b"")], device=1)
    assert window._csv is None, "the analyser must not open a recording"
    assert window._monitors[1].running, "it is still marked as running"


def test_the_controlling_device_opens_and_closes_it(window, tmp_path):
    add_second_device(window, label="ms")
    window._monitors[1].config.controls_recording = False

    feed(window, [(1.0, START_CMD, b"")], device=0)
    assert window._csv is not None, "the oven starts the recording"

    feed(window, [(500.0, STOP_CMD, b"")], device=0)
    assert window._csv is None, "and ends it, whatever the analyser is doing"


def test_a_passenger_cannot_hold_the_file_open(window):
    """The oven's run has ended; a still-running analyser must not extend it."""
    add_second_device(window, label="ms")
    window._monitors[1].config.controls_recording = False

    feed(window, [(1.0, START_CMD, b"")], device=0)
    feed(window, [(2.0, START_CMD, b"")], device=1)
    feed(window, [(500.0, STOP_CMD, b"")], device=0)
    assert window._csv is None


def test_a_passenger_still_contributes_its_columns(window, tmp_path):
    import csv as csvmod

    add_second_device(window, label="ms")
    window._monitors[1].config.controls_recording = False
    feed_together(
        window,
        [
            (0, a_run(start_at=1.0, stop_at=200.0, until=210.0)),
            # No start or stop commands from the analyser at all: just data.
            (1, [(float(t) + 0.5, STATUS_REQ, status_reply(20.0 + t * 0.1, 0.5))
                 for t in range(210)]),
        ],
    )
    written = sorted((tmp_path / "sessions").glob("*.csv"))
    assert len(written) == 1
    rows = list(csvmod.reader(written[0].open()))
    header, body = rows[0], rows[1:]
    column = header.index("ms.sample_temperature (degC)")
    assert any(r[column] for r in body), "the analyser's data must be in the file"


def test_both_controlling_devices_must_stop_before_the_file_closes(window):
    # Two ovens, both running experiments: the file spans both.
    add_second_device(window, label="oven2")
    assert all(m.config.controls_recording for m in window._monitors)

    feed(window, [(1.0, START_CMD, b"")], device=0)
    feed(window, [(2.0, START_CMD, b"")], device=1)
    feed(window, [(500.0, STOP_CMD, b"")], device=0)
    assert window._csv is not None, "the second oven is still running"
    feed(window, [(600.0, STOP_CMD, b"")], device=1)
    assert window._csv is None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))


# ----- recording an instrument nobody has decoded yet ------------------------


def test_a_device_with_no_profile_can_still_be_recorded(qapp, tmp_path, monkeypatch):
    """The raw sidecar exists precisely for the undecoded case.

    Requiring a profile to press Start meant the one situation the raw file was
    built for was the one situation it could not be produced in — while the
    panel said to start recording by hand.
    """
    from lan_sniffer.ui import main_window as mw

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    w._output_dir = tmp_path / "sessions"
    w._device_forms[0].set_label("spectrometer")
    w._device_forms[0].set_address("172.16.0.1")
    w._device_forms[0].save()
    arm(w)
    w._update_controls()

    assert w._start_btn.isEnabled(), "Start must not depend on having a profile"

    w._open_session(manual=True)
    assert w._csv is not None, "a session should have opened"
    feed(w, [(float(t), IDLE_REQ, b"\x01\x02\x03\x04") for t in range(5)])
    w._close_session(manual=True)
    w.close()

    raw = list((tmp_path / "sessions").glob("*.raw.jsonl"))
    assert raw, "the traffic must be on disk even with nothing named"
    assert raw[0].stat().st_size > 0


def test_the_banner_does_not_read_as_a_failed_recording(qapp, tmp_path, monkeypatch):
    """With no signals named there are no rows, and '0 rows' looks broken."""
    from lan_sniffer.ui import main_window as mw

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    w._output_dir = tmp_path / "sessions"
    w._device_forms[0].set_address("172.16.0.1")
    w._device_forms[0].save()
    arm(w)
    w._open_session(manual=True)
    feed(w, [(float(t), IDLE_REQ, b"\x01\x02\x03\x04") for t in range(5)])
    w._update_session_label()
    text = w._banner.text()
    w._close_session(manual=True)
    w.close()

    assert "RECORDING" in text
    assert "raw only" in text
    assert "0 rows" not in text


# ----- a device read from Questor's web interface ----------------------------


def test_a_questor_device_records_beside_a_sniffed_one(qapp, tmp_path, monkeypatch):
    """The point of the whole exercise: both instruments, one file, one clock."""
    from lan_sniffer.readers.questor import QuestorClient
    from lan_sniffer.ui import main_window as mw

    fixture = (Path(__file__).parent / "fixtures" / "questor_results.xml").read_bytes()

    class Canned:
        """A fresh result every time, as a live instrument produces."""

        name = "fake"

        def __init__(self):
            self.n = 0

        def post(self, url, body, timeout_s):
            self.n += 1
            stamp = f"2026-08-31T13:{14 + self.n // 60:02d}:{self.n % 60:02d}.000"
            return fixture.replace(b"2026-08-31T13:14:35.527", stamp.encode())

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    w._output_dir = tmp_path / "sessions"
    configure(w, 0, "dsc", "169.254.93.1")
    w._add_device()
    ms = w._monitors[1]
    # Through the form, as the UI does, so the column prefix is recomputed.
    w._device_forms[1].set_label("ms")
    w._device_forms[1].save()
    w._assign_prefixes()
    ms.config.questor_host = "localhost"
    ms.config.controls_recording = False
    # The whole run replays in milliseconds, so the rate gate would allow one
    # poll and it would land before the session opened.
    ms.config.questor_interval_s = 0.0
    ms.questor = QuestorClient()
    ms.questor.transport = Canned()
    # Priming, the way start_capture does: the tag names have to be known
    # before a session fixes its columns.
    for entry in ms.questor.poll():
        ms._questor_tags.extend(entry.values)
        ms._questor_units.update(entry.units)
    ms.questor.reset()
    ms._next_questor = 0.0
    arm(w)

    feed(w, a_run(start_at=5.0, stop_at=40.0, until=50.0))
    w.close()

    files = list((tmp_path / "sessions").glob("*.csv"))
    assert files, "a session should have been recorded"
    text = files[0].read_text(encoding="utf-8")
    header = text.splitlines()[0]
    assert "ms.V1_C_O2" in header, header
    assert "dsc.sample_temperature" in header, header
    # Written to nine significant figures, as every other column is.
    assert "73.2416306" in text, "Questor's value should be in the file"
    assert "2026-08-31" in text, "its own timestamps, not the sniffer's"


def test_a_questor_device_cannot_open_or_close_a_session(qapp, tmp_path, monkeypatch):
    """Questor is always acquiring - it has no experiment to start or stop."""
    from lan_sniffer.ui import main_window as mw

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    w._output_dir = tmp_path / "sessions"
    w._device_forms[0].set_label("ms")
    w._monitors[0].config.questor_host = "localhost"
    w._monitors[0].config.controls_recording = False
    arm(w)
    assert w._monitors[0].reads_questor
    assert w._monitors[0].detector is None
    w.close()
