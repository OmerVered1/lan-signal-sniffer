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


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from lan_sniffer.ui import main_window as mw

    monkeypatch.setattr(mw, "PROFILE_DIR", tmp_path / "profiles")
    w = mw.MainWindow()
    index = w._profile_box.findText("Setaram DSC (Setline)")
    assert index >= 0, "the DSC profile must be loadable"
    w._profile_box.setCurrentIndex(index)
    w._output_dir = tmp_path / "sessions"
    w._device.setEditText("169.254.93.1")
    yield w
    w.close()


def status_reply(temperature: float, heat_flow: float) -> bytes:
    """A 23-byte packed status frame, the shape the real DSC replies with."""
    body = bytearray(bytes.fromhex("0008000100011b03000110370a0001") + b"\x00" * 8)
    struct.pack_into(">f", body, 15, temperature)
    struct.pack_into(">f", body, 19, heat_flow)
    return bytes(body)


def feed(window, exchanges) -> None:
    """Push request/reply pairs through the window the way capture does."""
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
        window._handle_requests(chunks)
        if window._decoder is not None:
            for sample in window._decoder.feed(chunks):
                if window._csv is not None:
                    window._csv.add(sample.ts, sample.values)


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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
