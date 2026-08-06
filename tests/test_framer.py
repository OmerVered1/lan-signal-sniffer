"""Framing inference across the protocol shapes lab instruments actually use."""

from __future__ import annotations

import struct

import pytest
import synth

from lan_sniffer.protocol.framer import analyze_flow, group_chunks_by_flow


def analyze(chunks):
    flows = group_chunks_by_flow(chunks)
    assert len(flows) == 1, "fixtures should produce exactly one connection"
    return analyze_flow(next(iter(flows.values())))


# ----- fixed-length binary (the C80 shape) ---------------------------------


def test_fixed_length_framing_is_recognised():
    result = analyze(synth.c80_capture())
    assert result.interaction == "request_response"
    assert result.request_spec.mode == "fixed"
    assert result.request_spec.frame_len == 6


def test_fixed_length_split_finds_both_polled_channels():
    result = analyze(synth.c80_capture())
    assert len(result.channels) == 2
    signatures = {c.signature for c in result.channels}
    assert signatures == {synth.C80_HF_CMD, synth.C80_T_CMD}


def test_each_channel_collects_one_reply_per_poll():
    result = analyze(synth.c80_capture(n_cycles=50))
    for channel in result.channels:
        assert channel.count == 50
        assert len(channel.payloads) == len(channel.timestamps)


def test_replies_are_captured_whole():
    result = analyze(synth.c80_capture())
    for channel in result.channels:
        assert {len(p) for p in channel.payloads} == {10}


def test_median_period_matches_the_poll_rate():
    result = analyze(synth.c80_capture(period=2.0))
    for channel in result.channels:
        assert channel.median_period() == pytest.approx(2.0, abs=1e-6)


# ----- length-prefixed binary ----------------------------------------------


def test_length_prefixed_header_is_located():
    result = analyze(synth.length_prefixed_capture())
    spec = result.request_spec
    assert spec.mode == "length_prefixed"
    assert (spec.len_offset, spec.len_size, spec.len_endian) == (2, 2, "big")
    assert spec.len_adjust == 4  # the 2-byte magic and the length field itself


def test_length_prefixed_channels_separate_by_command_body():
    result = analyze(synth.length_prefixed_capture(n_cycles=60))
    assert len(result.channels) == 3
    for channel in result.channels:
        assert channel.count == 60


# ----- Modbus/TCP: fixed-length requests carrying a transaction id ---------


def test_modbus_read_requests_are_correctly_called_fixed_length():
    # Real Modbus read requests are all 12 bytes; "fixed" is the honest
    # description, and the length field does not need to be found to parse them.
    result = analyze(synth.modbus_capture())
    assert result.request_spec.mode == "fixed"
    assert result.request_spec.frame_len == 12


def test_incrementing_transaction_id_does_not_split_channels():
    # Without signature masking this would produce one channel per sample.
    result = analyze(synth.modbus_capture(n_cycles=100))
    assert len(result.channels) == 2
    for channel in result.channels:
        assert channel.count == 100


def test_masked_signature_positions_are_reported_not_hidden():
    result = analyze(synth.modbus_capture())
    assert any("vary like a counter" in w for w in result.warnings)
    assert ".." in result.channels[0].signature_hex


def test_masked_signature_still_matches_a_live_request():
    result = analyze(synth.modbus_capture())
    channel = result.channels[0]
    hits = 0
    for txid in (7, 4096, 65535):
        probe = bytearray(channel.signature)
        probe[0:2] = struct.pack(">H", txid)
        hits += channel.matches(bytes(probe))
    assert hits == 3


# ----- text / SCPI ----------------------------------------------------------


def test_scpi_stream_is_read_as_text():
    result = analyze(synth.scpi_capture())
    assert result.request_spec.mode == "text"
    assert result.request_spec.delimiter == b"\n"


def test_scpi_commands_separate_into_channels():
    result = analyze(synth.scpi_capture())
    signatures = {c.signature for c in result.channels}
    assert signatures == {b"MEAS:TEMP?\n", b"MEAS:HEAT?\n"}


# ----- device-push streams --------------------------------------------------


def test_unprompted_stream_is_detected():
    result = analyze(synth.push_capture())
    assert result.interaction == "server_push"
    assert len(result.channels) == 1
    assert result.channels[0].count == 200


# ----- fallback -------------------------------------------------------------


def test_unstructured_traffic_falls_back_to_one_frame_per_segment():
    # Varying lengths with no length field and no delimiter: the honest answer
    # is that each segment is a frame, not a confident guess.
    exchanges = []
    for i in range(30):
        req = bytes([0x80 + (i % 3)]) * (4 + (i % 5))
        exchanges.append((float(i), req, i + 0.01, b"\xff\xee" * 4))
    result = analyze(synth.build_capture(exchanges))
    assert result.request_spec.mode == "single_segment"
    assert result.request_spec.confidence < 0.6


def test_analysis_reports_how_much_it_saw():
    result = analyze(synth.c80_capture(n_cycles=20))
    assert result.request_frames == 40
    assert result.response_bytes == 400


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
