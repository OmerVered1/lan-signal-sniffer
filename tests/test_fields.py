"""Field discovery: does the generic scan find the signals that are really there?

The C80 cases are the ones that matter most. Its frame layout was reverse
engineered by hand from a Wireshark capture and is recorded in
keithley-smu-control/calorimeter_reader.py, so it is the only ground truth
available. Nothing in the scanner knows about it — if the generic path
rediscovers heat flow and temperature as big-endian float32 at payload offset 6,
the approach works on a device nobody has decoded yet.
"""

from __future__ import annotations

import struct

import numpy as np
import pytest
import synth

from lan_sniffer.protocol.fields import decode_field, scan_channel
from lan_sniffer.protocol.framer import analyze_flow, group_chunks_by_flow


def channels_of(chunks):
    flows = group_chunks_by_flow(chunks)
    return analyze_flow(next(iter(flows.values()))).channels


def channel_named(chunks, signature):
    for channel in channels_of(chunks):
        if channel.signature == signature:
            return channel
    raise AssertionError(f"no channel with signature {signature!r}")


# ----- C80 ground truth -----------------------------------------------------


def test_c80_heat_flow_is_rediscovered_as_float32_be_at_offset_6():
    channel = channel_named(synth.c80_capture(), synth.C80_HF_CMD)
    best = scan_channel(channel.payloads).candidates[0]
    assert (best.offset, best.encoding) == (6, "f32be")


def test_c80_temperature_is_rediscovered_as_float32_be_at_offset_6():
    channel = channel_named(synth.c80_capture(), synth.C80_T_CMD)
    best = scan_channel(channel.payloads).candidates[0]
    assert (best.offset, best.encoding) == (6, "f32be")


def test_c80_recovered_values_match_the_transmitted_signal():
    chunks = synth.c80_capture(n_cycles=60, period=1.0)
    channel = channel_named(chunks, synth.C80_HF_CMD)
    best = scan_channel(channel.payloads).candidates[0]
    got = decode_field(channel.payloads, best.offset, best.encoding)
    expected = [synth.heat_flow(i * 1.0) for i in range(60)]
    assert np.allclose(got, expected, rtol=1e-6)


def test_c80_echoed_request_bytes_do_not_outrank_the_measurement():
    # The first six bytes of every reply echo the request, so they are constant
    # within a channel. Constant fields must never win.
    channel = channel_named(synth.c80_capture(), synth.C80_HF_CMD)
    scan = scan_channel(channel.payloads)
    assert not scan.candidates[0].is_constant
    constants = [c for c in scan.candidates if c.is_constant]
    assert all(c.score < scan.candidates[0].score for c in constants)


def test_misaligned_float_readings_are_rejected_outright():
    # Reading the float one byte early spans the request echo and produces
    # denormal values, which is the signature of a bad alignment.
    channel = channel_named(synth.c80_capture(), synth.C80_HF_CMD)
    scan = scan_channel(channel.payloads)
    everything = list(scan.candidates)
    for cand in scan.candidates:
        everything.extend(cand.alternatives)
    assert not any(
        c.offset in (4, 5) and c.encoding.startswith("f32") for c in everything
    )


def test_narrower_readings_of_the_same_bytes_are_offered_as_alternatives():
    # The top two bytes of the float also decode as a plausible u16. That
    # reading is a fragment, not a rival, so it belongs under the winner.
    channel = channel_named(synth.c80_capture(), synth.C80_HF_CMD)
    best = scan_channel(channel.payloads).candidates[0]
    assert any(
        alt.encoding.startswith(("u16", "i16", "u32", "i32"))
        for alt in best.alternatives
    )


# ----- integer-encoded values (Modbus) --------------------------------------


def test_modbus_scaled_integer_register_is_found():
    chunks = synth.modbus_capture(n_cycles=100)
    channels = channels_of(chunks)
    # The furnace channel polls register 0x0010; its value sits in the first
    # data register, after the 7-byte MBAP header and the 2-byte PDU header.
    furnace = [c for c in channels if c.signature[8:10] == b"\x00\x10"][0]
    best = scan_channel(furnace.payloads).candidates[0]
    assert best.offset == 9
    assert best.encoding in ("u16be", "i16be")


def test_transaction_counter_in_the_reply_does_not_win():
    # The echoed transaction id is a flawless ramp and would otherwise score
    # better than any real sensor.
    chunks = synth.modbus_capture(n_cycles=100)
    scan = scan_channel(channels_of(chunks)[0].payloads)
    assert scan.candidates[0].offset != 0
    counter = next((c for c in scan.candidates if c.offset == 0), None)
    if counter is not None:
        assert counter.is_counter
        assert counter.score < scan.candidates[0].score


# ----- text replies ---------------------------------------------------------


def test_scpi_reply_number_is_extracted():
    channel = channel_named(synth.scpi_capture(), b"MEAS:TEMP?\n")
    best = scan_channel(channel.payloads).candidates[0]
    assert best.encoding == "ascii#0"
    got = decode_field(channel.payloads, 0, "ascii#0")
    assert np.allclose(got, [synth.temperature(i * 1.0) for i in range(120)], rtol=1e-5)


# ----- device-push streams --------------------------------------------------


def test_both_floats_in_a_pushed_frame_are_found_separately():
    channel = channels_of(synth.push_capture())[0]
    scan = scan_channel(channel.payloads)
    offsets = {(c.offset, c.encoding) for c in scan.candidates[:2]}
    assert offsets == {(0, "f32be"), (4, "f32be")}


# ----- guard rails ----------------------------------------------------------


def test_too_few_samples_is_reported_rather_than_guessed():
    payloads = [struct.pack(">f", 1.0 * i) for i in range(3)]
    scan = scan_channel(payloads)
    assert scan.candidates == []
    assert any("at least" in w for w in scan.warnings)


def test_odd_length_replies_are_skipped_and_counted():
    good = [synth.C80_HF_CMD + struct.pack(">f", synth.heat_flow(i)) for i in range(40)]
    scan = scan_channel(good + [b"\x00\x01"])
    assert scan.samples_dropped == 1
    assert scan.samples_used == 40
    assert any("skipped" in w for w in scan.warnings)


def test_empty_channel_does_not_crash():
    scan = scan_channel([])
    assert scan.candidates == []
    assert scan.warnings


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
