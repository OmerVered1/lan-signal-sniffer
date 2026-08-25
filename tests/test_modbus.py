"""Reading values an instrument publishes on request, rather than sniffing them.

A process mass spectrometer computes its concentrations in software and never
puts them on the wire, so no amount of watching traffic recovers them. Its
software does publish them through a Modbus slave, which exists to be polled.

The register formats are taken from the Questor5 manual, and its own worked
example is used as ground truth below: a concentration of 42.1466% stored in the
legacy paired format gives registers 1286 and 8238.
"""

from __future__ import annotations

import struct

import pytest

from lan_sniffer.readers.modbus import (
    READ_HOLDING_REGISTERS,
    ModbusError,
    RegisterSpec,
    build_request,
    crc16,
    decode_ieee754,
    decode_legacy_paired,
    decode_single,
    parse_response,
    plan_reads,
)


def rtu_reply(unit: int, words) -> bytes:
    body = bytes([unit, READ_HOLDING_REGISTERS, len(words) * 2])
    for w in words:
        body += struct.pack(">H", w)
    return body + struct.pack("<H", crc16(body))


def tcp_reply(unit: int, words, transaction: int = 1) -> bytes:
    body = bytes([unit, READ_HOLDING_REGISTERS, len(words) * 2])
    for w in words:
        body += struct.pack(">H", w)
    return struct.pack(">HHH", transaction, 0, len(body)) + body


# ----- framing --------------------------------------------------------------


def test_crc_matches_the_known_modbus_vector():
    # The canonical check value for "123456789" under the Modbus polynomial.
    assert crc16(b"123456789") == 0x4B37


def test_an_rtu_request_carries_a_crc_and_no_header():
    frame = build_request(1, 40001 - 40001, 2, framing="rtu_tcp")
    assert frame[0] == 1 and frame[1] == READ_HOLDING_REGISTERS
    assert crc16(frame[:-2]) == struct.unpack("<H", frame[-2:])[0]
    assert len(frame) == 8


def test_a_tcp_request_carries_an_mbap_header_and_no_crc():
    frame = build_request(1, 0, 2, framing="tcp", transaction=7)
    txid, protocol, length = struct.unpack(">HHH", frame[:6])
    assert (txid, protocol, length) == (7, 0, 6)
    assert len(frame) == 12


def test_both_framings_round_trip():
    assert parse_response(rtu_reply(1, [1286, 8238]), "rtu_tcp") == [1286, 8238]
    assert parse_response(tcp_reply(1, [1286, 8238]), "tcp") == [1286, 8238]


def test_a_corrupt_frame_is_reported_as_a_framing_mismatch():
    """The likeliest cause is the wrong framing, which otherwise looks dead."""
    bad = bytearray(rtu_reply(1, [5, 6]))
    bad[-1] ^= 0xFF
    with pytest.raises(ModbusError, match="framing"):
        parse_response(bytes(bad), "rtu_tcp")


def test_reading_tcp_frames_as_rtu_does_not_silently_succeed():
    with pytest.raises(ModbusError):
        parse_response(tcp_reply(1, [1, 2, 3, 4]), "rtu_tcp")


def test_a_slave_exception_says_what_went_wrong():
    body = bytes([1, READ_HOLDING_REGISTERS | 0x80, 0x02])
    frame = body + struct.pack("<H", crc16(body))
    with pytest.raises(ModbusError, match="illegal data address"):
        parse_response(frame, "rtu_tcp")


def test_a_truncated_reply_is_refused():
    with pytest.raises(ModbusError, match="too short"):
        parse_response(b"\x01\x03", "rtu_tcp")


# ----- the register formats from the manual ---------------------------------


def test_the_manuals_legacy_paired_example():
    """42.1466% is stored as 1286 and 8238 — the manual's own worked example."""
    assert decode_legacy_paired(1286, 8238) == pytest.approx(42.1466, abs=1e-6)


def test_the_legacy_split_is_reversible():
    for value in (0.00235, 0.4907, 42.1466, 115.663):
        scaled = int(round(value * 1_000_000))
        high, low = divmod(scaled, 32767)
        assert decode_legacy_paired(high, low) == pytest.approx(value, abs=1e-6)


def test_ieee754_carries_the_value_exactly():
    for value in (115.663002, 0.00236163, -1.9029):
        high, low = struct.unpack(">HH", struct.pack(">f", value))
        assert decode_ieee754(high, low) == pytest.approx(value, rel=1e-6)


def test_word_order_is_a_setting_not_an_assumption():
    """Read the wrong way round the value is nonsense, not merely inaccurate."""
    high, low = struct.unpack(">HH", struct.pack(">f", 115.663))
    assert decode_ieee754(high, low, word_swap=False) == pytest.approx(115.663, rel=1e-6)
    swapped = decode_ieee754(high, low, word_swap=True)
    assert not (100 < swapped < 130)


def test_single_register_scaling_spans_the_configured_limits():
    assert decode_single(0, 0.0, 100.0, 9999) == pytest.approx(0.0)
    assert decode_single(9999, 0.0, 100.0, 9999) == pytest.approx(100.0)
    assert decode_single(5000, 0.0, 100.0, 9999) == pytest.approx(50.005, abs=1e-3)
    # A narrow span is the point of this format: precision where it is needed.
    assert decode_single(2000, 0.4, 0.6, 4000) == pytest.approx(0.5, abs=1e-6)


# ----- specs and read planning ----------------------------------------------


def test_a_spec_decodes_through_its_scale_and_bias():
    spec = RegisterSpec(name="V1_I_4", address=40001, format="ieee754", scale=2.0, bias=1.0)
    high, low = struct.unpack(">HH", struct.pack(">f", 10.0))
    assert spec.decode([high, low]) == pytest.approx(21.0)


def test_paired_formats_claim_two_registers_and_single_ones_claim_one():
    assert RegisterSpec("a", 0, "ieee754").registers == 2
    assert RegisterSpec("a", 0, "legacy_paired").registers == 2
    assert RegisterSpec("a", 0, "single").registers == 1
    assert RegisterSpec("a", 0, "uint16").registers == 1


def test_an_unknown_format_is_refused_rather_than_guessed():
    with pytest.raises(ValueError, match="unknown register format"):
        RegisterSpec("a", 0, "float").decode([1, 2])


def test_nearby_registers_are_fetched_in_one_read():
    """Seven round trips would sample one gas composition at seven moments."""
    specs = [RegisterSpec(f"v{i}", 40000 + i * 2, "ieee754") for i in range(7)]
    reads = plan_reads(specs)
    assert len(reads) == 1
    start, count = reads[0]
    assert start == 40000 and count == 14


def test_distant_registers_are_read_separately():
    specs = [
        RegisterSpec("near", 40000, "ieee754"),
        RegisterSpec("far", 41000, "ieee754"),
    ]
    assert len(plan_reads(specs, max_span=120)) == 2


def test_planning_no_registers_asks_for_nothing():
    assert plan_reads([]) == []


def test_a_spec_survives_the_round_trip_through_json():
    spec = RegisterSpec("V1_I_18", 40003, "legacy_paired", unit="%", scale=1.5)
    again = RegisterSpec.from_dict(spec.to_dict())
    assert again == spec


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))


# ----- end to end against a real socket -------------------------------------


@pytest.fixture(params=["rtu_tcp", "tcp"])
def slave(request):
    """Run the fake slave in a thread and yield (host, port, framing)."""
    import subprocess
    import sys
    import time
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    framing = request.param
    port = 5030 if framing == "rtu_tcp" else 5031
    proc = subprocess.Popen(
        [sys.executable, str(root / "tools" / "fake_modbus_slave.py"),
         "--port", str(port), "--framing", framing],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    for _ in range(80):
        try:
            import socket as sk

            with sk.create_connection(("127.0.0.1", port), 0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        proc.terminate()
        pytest.skip("the fake slave did not start")
    yield "127.0.0.1", port, framing
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def seven_channels():
    return [
        RegisterSpec("V1_I_18", 40000, "ieee754", unit="%"),
        RegisterSpec("V1_I_2", 40002, "ieee754", unit="%"),
        RegisterSpec("V1_I_4", 40004, "ieee754", unit="%"),
        RegisterSpec("V1_I_32", 40006, "ieee754", unit="%"),
        RegisterSpec("V1_I_44", 40008, "ieee754", unit="%"),
        RegisterSpec("V1_I_28", 40010, "ieee754", unit="%"),
        RegisterSpec("V1_I_40", 40012, "ieee754", unit="%"),
    ]


def test_every_channel_is_read_over_a_real_socket(slave):
    from lan_sniffer.readers.modbus import ModbusClient

    host, port, framing = slave
    with ModbusClient(host, port, unit=1, framing=framing) as client:
        values = client.read(seven_channels())
    assert set(values) == {s.name for s in seven_channels()}
    # The carrier gas dominates; the trace species are small. Both must survive
    # the round trip, which is the whole point of the IEEE 754 format.
    assert 100 < values["V1_I_4"] < 130
    assert 0 < values["V1_I_44"] < 1


def test_the_seven_values_arrive_in_one_round_trip(slave):
    """Consecutive registers must be fetched together.

    Seven separate reads would sample one gas composition at seven different
    moments, which is exactly what a coupled measurement must not do.
    """
    from lan_sniffer.readers.modbus import ModbusClient

    host, port, framing = slave
    reads = plan_reads(seven_channels())
    assert len(reads) == 1
    with ModbusClient(host, port, framing=framing) as client:
        assert len(client.read(seven_channels())) == 7


def test_repeated_polls_reuse_one_connection(slave):
    from lan_sniffer.readers.modbus import ModbusClient

    host, port, framing = slave
    client = ModbusClient(host, port, framing=framing)
    try:
        first = client.read(seven_channels())
        assert client.connected
        second = client.read(seven_channels())
        assert set(first) == set(second)
    finally:
        client.close()
    assert not client.connected


def test_the_wrong_framing_fails_loudly_rather_than_returning_rubbish(slave):
    """Picking the wrong option in the vendor dialog must be diagnosable."""
    from lan_sniffer.readers.modbus import ModbusClient

    host, port, framing = slave
    wrong = "tcp" if framing == "rtu_tcp" else "rtu_tcp"
    client = ModbusClient(host, port, framing=wrong, timeout=1.0)
    with pytest.raises(Exception):
        client.read(seven_channels())
    client.close()
