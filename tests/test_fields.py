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




# ----- scales other than degrees and milliwatts -----------------------------


def scientific_channel(n=200):
    """Replies shaped like a process mass spectrometer's.

    A little-endian millisecond clock, an ion current in amps, and a
    percentage — the natural units of the instrument, two of which sit far
    below anything a thermal analyser reports.
    """
    import math

    payloads = []
    for i in range(n):
        body = bytearray(b"\x00" * 28)
        struct.pack_into("<I", body, 11, 950_000_000 + i * 250)
        struct.pack_into("<f", body, 19, 3.34e-7 + 2e-8 * math.sin(i / 40))
        struct.pack_into("<f", body, 23, 117.40 + 0.5 * math.sin(i / 30))
        payloads.append(bytes(body))
    return payloads


def test_an_ion_current_in_amps_is_found():
    """Regression: the plausibility floor was set for degrees and milliwatts.

    At 1e-3 it scored every ion current, vacuum pressure and similar reading
    at zero, so on a mass spectrometer the real signals ranked below misaligned
    noise and the top candidate was a clock.
    """
    scan = scan_channel(scientific_channel())
    best = scan.candidates[0]
    assert (best.offset, best.encoding) == (19, "f32le")
    assert best.maximum < 1e-5, "this is an ion current, not a temperature"


def test_a_percentage_alongside_it_is_also_found():
    scan = scan_channel(scientific_channel())
    top_two = {(c.offset, c.encoding) for c in scan.candidates[:2]}
    assert (19, "f32le") in top_two and (23, "f32le") in top_two


def test_a_counter_read_as_a_float_is_demoted():
    """A clock advances at a constant rate; that is what marks it out."""
    payloads = []
    for i in range(200):
        body = bytearray(b"\x00" * 8)
        struct.pack_into("<I", body, 0, 950_000_000 + i * 250)
        payloads.append(bytes(body))
    everything = []
    for cand in scan_channel(payloads).candidates:
        everything.append(cand)
        everything.extend(cand.alternatives)
    clock = [c for c in everything if (c.offset, c.encoding) == (0, "f32le")]
    assert clock and clock[0].is_counter, "a steadily advancing float is a clock"


def test_a_slow_curve_is_not_mistaken_for_a_clock():
    """The counterpart, and the more damaging error of the two.

    A thermal wave sampled over 40 s of its 261 s period only ever rises, and
    its slope varies by about a sixth. Condemning that dropped the C80's heat
    flow off the candidate list entirely — and an absent signal cannot be
    overruled by the user, while a clock sitting near the top plainly can.
    """
    channel = channel_named(synth.c80_capture(n_cycles=40), synth.C80_HF_CMD)
    best = scan_channel(channel.payloads).candidates[0]
    assert (best.offset, best.encoding) == (6, "f32be")
    assert not best.is_counter


def test_a_reading_spanning_many_decades_is_demoted():
    """Widening the floor lets more misalignments look plausible; this is the
    check that separates them again."""
    import math

    payloads = []
    for i in range(120):
        body = bytearray(b"\x00" * 8)
        # A value sweeping twelve orders of magnitude: no sensor does this.
        struct.pack_into("<f", body, 0, 10.0 ** (-14 + 12 * (i / 120)))
        struct.pack_into("<f", body, 4, 25.0 + 0.5 * math.sin(i / 20))
        payloads.append(bytes(body))
    best = scan_channel(payloads).candidates[0]
    assert best.offset == 4, "the steady reading should outrank the sweep"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
