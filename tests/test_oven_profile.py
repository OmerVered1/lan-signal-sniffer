"""The Setaram oven profile, checked against the frame it was derived from.

Identification of this instrument was bit-exact rather than statistical: one
43-byte status frame decoded to the seven numbers on one row of Calisto's own
export. That frame is reproduced here, so the profile is pinned to the evidence
rather than to a set of offsets someone once typed.

The awkward part of this device, and the reason it went unidentified at first,
is that the same request answers in two shapes — a 6-byte "nothing new" ack and
the full frame — with the ack the more common of the two.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import synth

from lan_sniffer.capture.reassembly import TCPReassembler
from lan_sniffer.protocol.profile import DeviceProfile, LiveDecoder

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "setaram_oven_calisto.json"

STATUS_REQ = bytes.fromhex("0008")
ACK = bytes.fromhex("000800010000")

# The row Calisto logged at the same moment as the frame below.
CALISTO_ROW = {
    "sample_temperature": 25.557554,
    "furnace_temperature": 22.730051,
    "heat_flow": 20287.716797,
    "humidity": 28.81,
    "heater_power": 3.784194,
    "carrier_gas_flow": 20.023611,
    "auxiliary_gas_flow": 0.0,
}


def status_frame(
    sample=22.557554, furnace=22.730051, heat_flow=20287.716797,
    humidity=28.81, power=3.784194, carrier=20.023611, auxiliary=0.0,
) -> bytes:
    """The 43-byte frame, exactly as captured on 2026-08-27.

    Note `sample` defaults to the value *on the wire*, which is 3.000 degC
    below what Calisto displays.
    """
    head = bytes.fromhex("0008000100011e04000e1c100a0000")
    body = b"".join(
        struct.pack(">f", v)
        for v in (sample, furnace, heat_flow, humidity, power, carrier, auxiliary)
    )
    assert len(head) + len(body) == 43
    return head + body


def profile() -> DeviceProfile:
    return DeviceProfile.from_dict(json.loads(PROFILE.read_text(encoding="utf-8")))


def feed(exchanges):
    asm = TCPReassembler(synth.DEVICE_IP)
    chunks = []
    c_seq = s_seq = 1000
    for ts, request, reply in exchanges:
        chunks += asm.add_segment(
            ts, synth.PEER_IP, 51234, synth.DEVICE_IP, 1210, c_seq, request
        )
        c_seq += len(request)
        if reply:
            chunks += asm.add_segment(
                ts + 0.01, synth.DEVICE_IP, 1210, synth.PEER_IP, 51234, s_seq, reply
            )
            s_seq += len(reply)
    decoder = LiveDecoder(profile())
    samples = decoder.feed(chunks)
    samples.extend(decoder.flush())
    return samples


def test_the_profile_is_valid():
    assert profile().validate() == []


def test_the_status_frame_decodes_to_the_calisto_row():
    samples = feed([(float(i), STATUS_REQ, status_frame()) for i in range(4)])
    assert samples
    got = samples[0].values
    for name, expected in CALISTO_ROW.items():
        assert abs(got[name] - expected) < 1e-4, f"{name}: {got[name]} != {expected}"


def test_sample_temperature_carries_calistos_three_degree_offset():
    """The wire reads 22.557554 and Calisto displays 25.557554, exactly.

    Measured during the isothermal hold, where Calisto's 3.3 s logging interval
    cannot masquerade as an offset: median +3.000000 over 7,358 frames.
    """
    got = feed([(float(i), STATUS_REQ, status_frame()) for i in range(4)])[0].values
    assert abs(got["sample_temperature"] - 25.557554) < 1e-4
    assert abs(got["furnace_temperature"] - 22.730051) < 1e-4


def test_the_short_ack_yields_no_reading_rather_than_a_wrong_one():
    """The ack outnumbers the real frame two to one on this instrument."""
    samples = feed(
        [(float(i), STATUS_REQ, ACK if i % 2 else status_frame()) for i in range(8)]
    )
    assert samples, "the full frames must still decode"
    assert all("sample_temperature" in s.values for s in samples)
    assert len(samples) == 4, f"one sample per full frame, got {len(samples)}"


def test_the_setpoint_is_read_as_a_double():
    """Read as the f32 in its top half it tracks temperature and reproduces none."""
    request = bytes.fromhex("000100100000")
    reply = bytes.fromhex("000100100000") + struct.pack(">d", 850.0)
    got = feed([(float(i), request, reply) for i in range(4)])[0].values
    assert abs(got["programmed_setpoint"] - 850.0) < 1e-9


def test_a_run_starts_and_stops_on_calistos_control_writes():
    spec = profile().session
    assert spec is not None
    assert spec["trigger_signatures"] == ["00040001000005"]
    assert spec["stop_signatures"] == ["00040001000002"]
    # Each is sent once, so requiring a streak would mean a run never starts.
    assert spec["start_streak"] == 1


# ----- the pressures Calisto shows but does not export ------------------------


def test_the_carrying_gas_pressure_decodes_in_millibar():
    """Identified by value: the only field in the capture in a pressure range.

    1431 to 1600 mBar over the run, against the 1525 mBar the panel shows at
    idle. The only other 1000-2000 value anywhere was a constant 1000.0, which
    is the programme's final temperature.
    """
    request = bytes.fromhex("000100140002")
    reply = request + struct.pack(">f", 1525.0)
    got = feed([(float(i), request, reply) for i in range(4)])[0].values
    assert abs(got["carrying_gas_pressure"] - 1525.0) < 1e-4


def test_the_gas_panel_family_shares_one_layout():
    """00010014xxxx is the panel; index 0000 is what proves it.

    Read the same way, 0000 reproduces Calisto's Carrier Gas Flow to a median
    difference of 0.000000 over 42,649 samples — so the family is the gas
    panel, and the offset and encoding used for the pressures are the ones
    already confirmed against the export for a flow.
    """
    profile_signals = {s.name: s for s in profile().signals}
    family = [
        profile_signals["carrying_gas_pressure"],
        profile_signals["protective_gas_pressure"],
    ]
    for spec in family:
        assert spec.signature.hex().startswith("00010014")
        assert spec.offset == 6
        assert spec.encoding == "f32be"
        assert spec.unit == "mBar"


def test_the_protective_gas_channel_is_flagged_as_positional():
    """It is constant zero, and so are three other channels.

    Nothing in the data separates it from them; it is index 3 of a family whose
    other three are confirmed. The notes have to say so, because a reader who
    assumes it was measured would trust a number that was inferred.
    """
    notes = profile().notes
    assert "position rather than by evidence" in notes
    assert "not a measurement" in notes


# ----- replies that carry more than one reading ------------------------------


def batch(records, header=bytes.fromhex("000800010001")):
    """A reply holding `records` readings, the way the oven packs them.

    43 bytes for the first, then 37 for each of the rest, with no header
    between them - which is what makes a naive decoder read the first and
    silently discard the others.
    """
    out = bytearray(header)
    for i, sample in enumerate(records):
        out += bytes.fromhex("0305000328") + bytes([43, i * 10]) + b"\x00\x00"
        out += b"".join(
            struct.pack(">f", v)
            for v in (sample, 21.0, 20287.716797, 28.81, 5.0, 20.0, 0.0)
        )
    return bytes(out)


def test_a_batched_reply_yields_every_reading_not_just_the_first():
    """The instrument buffers when the software logs faster than it polls.

    A decoder that reads only the first record records a tenth of the
    experiment and gives no sign that the rest existed - the readings it does
    keep are perfectly correct.
    """
    wanted = [21.1, 21.2, 21.3, 21.4, 21.5, 21.6, 21.7, 21.8, 21.9, 22.0]
    reply = batch(wanted)
    assert len(reply) == 376, f"ten records should be 376 bytes, got {len(reply)}"

    samples = feed([(float(i), STATUS_REQ, reply) for i in range(3)])
    got = [s.values["sample_temperature"] for s in samples]
    # The first batch contributes its newest reading only; the two after it
    # contribute all ten each.
    assert len(got) == 21, f"expected ten readings per reply, got {len(got)}"
    # The profile adds Calisto's +3.000 to every one of them.
    assert [round(v - 3.0, 4) for v in got[1:11]] == wanted


def test_readings_in_a_batch_are_spread_across_the_interval_they_cover():
    """All ten sharing the reply's timestamp would stack them on one instant."""
    reply = batch([21.0 + i * 0.1 for i in range(10)])
    samples = feed([(float(i), STATUS_REQ, reply) for i in range(3)])
    # The first batch contributes only its newest reading: there is no earlier
    # reply to measure the interval against, so the other nine have no known
    # time. Every batch after it is spread across the second it covers.
    later = [s for s in samples if s.ts > 1.0]
    stamps = sorted(round(s.ts, 6) for s in later)
    assert len(set(stamps)) == len(later), "every reading needs its own timestamp"
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert max(gaps) - min(gaps) < 0.02, f"spacing should be even, got {gaps}"
    assert abs(max(gaps) - 0.1) < 0.02, f"ten readings in a second, got {max(gaps)}"


def test_a_reply_that_does_not_divide_into_records_falls_back_to_one():
    """Two replies concatenated put a second header in the middle.

    Every record after it shifts, and reading straight through produces
    plausible-looking numbers that are wrong. Losing the batch costs a fraction
    of a second; emitting it wrong costs more, and silently.
    """
    damaged = batch([21.0] * 5) + bytes.fromhex("000800010001") + batch([99.0] * 3)[6:]
    assert (len(damaged) - 6) % 37 != 0, "this fixture must be unaligned"

    samples = feed([(float(i), STATUS_REQ, damaged) for i in range(3)])
    for s in samples:
        # 99.0 would be a record read across the second header.
        assert abs(s.values["sample_temperature"] - 24.0) < 1e-4
        assert abs(s.values["heat_flow"] - 20287.716797) < 1e-3


def test_a_signal_without_a_stride_is_not_repeated_into_later_records():
    """It has one reading per reply; copying it would invent samples."""
    request = bytes.fromhex("000100140002")
    reply = request + struct.pack(">f", 1525.0)
    samples = feed([(float(i), request, reply) for i in range(4)])
    assert all("carrying_gas_pressure" in s.values for s in samples)
    assert len(samples) == 4, f"one reading per reply, got {len(samples)}"
