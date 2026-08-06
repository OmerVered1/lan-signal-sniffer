"""TCP reassembly: ordering, retransmits, holes, and boundary preservation."""

from __future__ import annotations

import pytest

from lan_sniffer.capture.reassembly import (
    C2S,
    MAX_PENDING_SEGMENTS,
    S2C,
    TCPReassembler,
)

DEVICE = "192.168.0.50"
PEER = "192.168.0.10"
DEV_PORT = 1210
PEER_PORT = 51000


def send(asm, seq, payload, ts=0.0, from_device=False, **flags):
    """Push one segment in either direction and return the emitted chunks."""
    if from_device:
        return asm.add_segment(
            ts, DEVICE, DEV_PORT, PEER, PEER_PORT, seq, payload, **flags
        )
    return asm.add_segment(
        ts, PEER, PEER_PORT, DEVICE, DEV_PORT, seq, payload, **flags
    )


def test_direction_is_derived_from_device_ip():
    asm = TCPReassembler(DEVICE)
    out = send(asm, 100, b"req")
    assert [c.direction for c in out] == [C2S]
    out = send(asm, 500, b"resp", from_device=True)
    assert [c.direction for c in out] == [S2C]


def test_in_order_segments_stream_through_in_sequence():
    asm = TCPReassembler(DEVICE)
    got = b""
    for i in range(5):
        for chunk in send(asm, 100 + i * 4, b"abcd", ts=float(i)):
            got += chunk.data
    assert got == b"abcd" * 5


def test_each_segment_stays_its_own_chunk():
    # The framer relies on this: one poll request is one segment, and merging
    # them would destroy the only unambiguous frame-boundary signal we have.
    asm = TCPReassembler(DEVICE)
    lengths = []
    for i in range(4):
        for chunk in send(asm, 100 + i * 6, bytes([i]) * 6):
            lengths.append(len(chunk.data))
    assert lengths == [6, 6, 6, 6]


def test_stream_offset_tracks_position_in_the_stream():
    asm = TCPReassembler(DEVICE)
    offsets = []
    for i in range(3):
        for chunk in send(asm, 100 + i * 4, b"wxyz"):
            offsets.append(chunk.stream_offset)
    assert offsets == [0, 4, 8]


def test_pure_retransmission_is_dropped():
    asm = TCPReassembler(DEVICE)
    assert len(send(asm, 100, b"abcd")) == 1
    assert send(asm, 100, b"abcd") == []
    assert len(send(asm, 104, b"efgh")) == 1


def test_partially_overlapping_retransmission_is_trimmed():
    asm = TCPReassembler(DEVICE)
    send(asm, 100, b"abcd")
    out = send(asm, 102, b"cdef")  # re-sends "cd", then two new bytes
    assert b"".join(c.data for c in out) == b"ef"


def test_reordered_segment_is_buffered_then_released_in_order():
    asm = TCPReassembler(DEVICE)
    send(asm, 100, b"aaaa")
    assert send(asm, 108, b"cccc") == []  # arrives early, held back
    out = send(asm, 104, b"bbbb")  # fills the hole, releases both
    assert b"".join(c.data for c in out) == b"bbbbcccc"


def test_reordering_preserves_per_segment_timestamps():
    asm = TCPReassembler(DEVICE)
    send(asm, 100, b"aaaa", ts=1.0)
    send(asm, 108, b"cccc", ts=3.0)
    out = send(asm, 104, b"bbbb", ts=2.0)
    assert [c.ts for c in out] == [2.0, 3.0]


def test_frame_split_across_packets_is_rejoined():
    asm = TCPReassembler(DEVICE)
    data = b""
    for chunk in send(asm, 100, b"\x00\x01\x00"):
        data += chunk.data
    for chunk in send(asm, 103, b"\x0a\x00\x01"):
        data += chunk.data
    assert data == b"\x00\x01\x00\x0a\x00\x01"


def test_syn_resets_the_stream():
    # Vendor software reconnecting must not leave a half-parsed frame behind.
    asm = TCPReassembler(DEVICE)
    send(asm, 100, b"abcd")
    send(asm, 999, b"", syn=True)
    out = send(asm, 1000, b"zzzz")
    assert b"".join(c.data for c in out) == b"zzzz"


def test_unfillable_hole_is_abandoned_and_reported_as_a_gap():
    asm = TCPReassembler(DEVICE)
    send(asm, 100, b"aaaa")  # establishes next_seq = 104
    emitted = []
    # Never send seq 104, so everything after it piles up behind the hole.
    for i in range(MAX_PENDING_SEGMENTS + 2):
        seq = 108 + i * 4
        emitted += send(asm, seq, b"bbbb", ts=float(i))
    assert emitted, "reassembler must give up rather than buffer for ever"
    assert emitted[0].gap_before == 4, "the 4 lost bytes should be reported"


def test_traffic_for_other_hosts_is_ignored():
    asm = TCPReassembler(DEVICE)
    assert asm.add_segment(0.0, "10.0.0.1", 1, "10.0.0.2", 2, 100, b"nope") == []


def test_connections_are_kept_separate():
    asm = TCPReassembler(DEVICE)
    a = asm.add_segment(0.0, PEER, 51000, DEVICE, DEV_PORT, 100, b"AAAA")
    b = asm.add_segment(0.0, PEER, 51001, DEVICE, DEV_PORT, 700, b"BBBB")
    assert a[0].flow != b[0].flow
    assert a[0].stream_offset == 0 and b[0].stream_offset == 0


def test_sequence_number_wraparound():
    asm = TCPReassembler(DEVICE)
    start = (1 << 32) - 6
    out = send(asm, start, b"abcdef")
    assert b"".join(c.data for c in out) == b"abcdef"
    out = send(asm, 0, b"ghij")  # wrapped past 2**32
    assert b"".join(c.data for c in out) == b"ghij"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
