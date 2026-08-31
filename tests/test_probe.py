"""Asking an instrument directly — the one place this app transmits.

Everything else here is passive by construction, so these tests are mostly
about the boundary: that a request is only ever one the instrument was already
seen to accept, that a command the vendor software sent once is not replayed as
though it were a poll, and that the whole thing refuses to open a socket until
the user has said the vendor software is closed.

The reply-reading test matters for a duller reason. There is no length prefix
in this protocol, so the end of a reply can only be inferred from a pause — and
a 24 KB answer arrives as many segments.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
import synth

from lan_sniffer.capture.reassembly import TCPReassembler
from lan_sniffer.readers.probe import (
    POLL_THRESHOLD,
    ObservedRequest,
    Probe,
    observed_requests,
)

POLL = bytes.fromhex("52000000030000000500000008000000")
ONE_OFF = bytes.fromhex("6a0000000e00000006000000")


def capture(poll_count=40, one_off_count=1):
    asm = TCPReassembler("172.16.0.1")
    chunks = []
    c_seq = s_seq = 1000
    t = 0.0
    for request, n in ((POLL, poll_count), (ONE_OFF, one_off_count)):
        for _ in range(n):
            chunks += asm.add_segment(
                t, synth.PEER_IP, 51234, "172.16.0.1", 30000, c_seq, request
            )
            c_seq += len(request)
            reply = b"\xaa" * 24
            chunks += asm.add_segment(
                t + 0.01, "172.16.0.1", 30000, synth.PEER_IP, 51234, s_seq, reply
            )
            s_seq += len(reply)
            t += 1.0
    return chunks


# ----- what may be sent ------------------------------------------------------


def test_only_requests_the_instrument_was_seen_to_accept_are_collected():
    found = observed_requests(capture(), "172.16.0.1")
    assert {r.payload for r in found} == {POLL, ONE_OFF}


def test_a_command_sent_once_is_not_treated_as_a_poll():
    """It may be a write. Replaying a write is not the same kind of act."""
    found = {r.payload: r for r in observed_requests(capture(), "172.16.0.1")}
    assert found[POLL].is_poll
    assert not found[ONE_OFF].is_poll
    assert found[POLL].count >= POLL_THRESHOLD


def test_only_one_field_can_be_varied_and_only_within_the_request():
    request = ObservedRequest(payload=POLL, count=40)
    varied = request.with_word(3, 0x99)
    assert len(varied) == len(POLL)
    assert varied[:12] == POLL[:12], "everything but the chosen field is untouched"
    assert varied[12:] == (0x99).to_bytes(4, "little")
    with pytest.raises(ValueError, match="outside"):
        request.with_word(9, 1)


def test_the_reply_sizes_the_capture_recorded_are_kept():
    """A different size when asked directly is the whole point of the exercise."""
    found = {r.payload: r for r in observed_requests(capture(), "172.16.0.1")}
    assert found[POLL].largest_reply == 24


# ----- talking to something --------------------------------------------------


class FakeInstrument:
    """Answers one request at a time, in several segments, like the real one."""

    def __init__(self, reply: bytes, segments: int = 1) -> None:
        self.reply = reply
        self.segments = segments
        self.received: list = []
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(1)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        with conn:
            while True:
                try:
                    request = conn.recv(65536)
                except OSError:
                    return
                if not request:
                    return
                self.received.append(request)
                step = max(1, len(self.reply) // self.segments)
                for i in range(0, len(self.reply), step):
                    conn.sendall(self.reply[i : i + step])
                    time.sleep(0.002)

    def close(self) -> None:
        self._server.close()


def test_a_reply_split_across_segments_is_read_whole():
    """There is no length prefix, so the end is only ever inferred from a pause."""
    big = bytes(range(256)) * 94  # 24,064 bytes, the size the MAX300 sends
    server = FakeInstrument(big, segments=16)
    try:
        with Probe("127.0.0.1", server.port, quiet_ms=120) as probe:
            reply = probe.ask(POLL)
    finally:
        server.close()
    assert reply.ok
    assert reply.reply == big, f"got {len(reply.reply)} of {len(big)} bytes"
    assert server.received == [POLL]


def test_an_instrument_that_says_nothing_is_reported_not_hung():
    server = FakeInstrument(b"", segments=1)
    try:
        with Probe("127.0.0.1", server.port, timeout_s=0.3, quiet_ms=50) as probe:
            reply = probe.ask(POLL)
    finally:
        server.close()
    assert not reply.ok


def test_a_refused_connection_is_an_error_not_a_crash():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing is listening now
    with pytest.raises(OSError):
        Probe("127.0.0.1", port, timeout_s=0.3).open()


# ----- the greeting a connection starts with ---------------------------------


def capture_with_greeting(greeting=(b"HELLO\x01", b"\x02SESSION")):
    """A connection whose first frames are a handshake, then normal polling."""
    asm = TCPReassembler("172.16.0.1")
    chunks = []
    c_seq = s_seq = 1000
    t = 0.0
    for frame in greeting:
        chunks += asm.add_segment(
            t, synth.PEER_IP, 51234, "172.16.0.1", 30000, c_seq, frame
        )
        c_seq += len(frame)
        chunks += asm.add_segment(
            t + 0.01, "172.16.0.1", 30000, synth.PEER_IP, 51234, s_seq, b"\x06"
        )
        s_seq += 1
        t += 0.5
    for _ in range(40):
        chunks += asm.add_segment(
            t, synth.PEER_IP, 51234, "172.16.0.1", 30000, c_seq, POLL
        )
        c_seq += len(POLL)
        chunks += asm.add_segment(
            t + 0.01, "172.16.0.1", 30000, synth.PEER_IP, 51234, s_seq, b"\xaa" * 24
        )
        s_seq += 24
        t += 1.0
    return chunks


def test_the_opening_frames_of_a_connection_are_recovered():
    """Sent once per connection, so nothing that counts repeats will see them."""
    from lan_sniffer.readers.probe import opening_sequence

    greeting = opening_sequence(capture_with_greeting(), "172.16.0.1")
    assert greeting[:2] == [b"HELLO\x01", b"\x02SESSION"]


def test_a_greeting_is_not_invented_when_the_capture_joined_late():
    """A capture that began mid-conversation has no byte zero.

    Returning the first thing it happens to see would hand back an ordinary
    poll dressed as a handshake, and replaying that proves nothing.
    """
    from lan_sniffer.readers.probe import opening_sequence

    chunks = capture_with_greeting()
    # Drop everything from the start of the stream, as a late capture would.
    late = [c for c in chunks if c.stream_offset > 200]
    assert opening_sequence(late, "172.16.0.1") == []


def test_the_greeting_is_not_mistaken_for_a_poll():
    """It is sent once, so it must not appear in the replayable request list."""
    found = {r.payload for r in observed_requests(capture_with_greeting()) if r.is_poll}
    assert POLL in found
    assert b"HELLO\x01" not in found
