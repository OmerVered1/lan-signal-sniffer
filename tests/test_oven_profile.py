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
    tail = decoder.flush()
    if tail is not None:
        samples.append(tail)
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
