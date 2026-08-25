"""A device that is read rather than watched, inside the app.

An instrument that computes its published values in software never puts them on
the wire, so sniffing cannot recover them. Reading its Modbus slave gives the
numbers its own software produced, and from the session's point of view such a
device should behave exactly like a sniffed one: same columns, same plot, same
file.
"""

from __future__ import annotations

import struct

import pytest

from lan_sniffer.monitor import DeviceConfig, DeviceMonitor
from lan_sniffer.protocol.framer import FramingSpec
from lan_sniffer.protocol.profile import (
    SOURCE_MODBUS,
    SOURCE_SNIFF,
    DeviceProfile,
)
from lan_sniffer.readers.modbus import RegisterSpec


def ms_profile(**kwargs) -> DeviceProfile:
    return DeviceProfile(
        name="MAX300",
        device_port=502,
        request_framing=FramingSpec(mode="single_segment"),
        source=SOURCE_MODBUS,
        modbus={"unit": 1, "framing": "rtu_tcp", "poll_interval_s": 0.0, **kwargs},
        registers=[
            RegisterSpec("V1_I_18", 40000, "ieee754", unit="%"),
            RegisterSpec("V1_I_4", 40002, "ieee754", unit="%"),
        ],
    )


class FakeReader:
    """Stands in for the Modbus client so the monitor can be driven offline."""

    def __init__(self, values=None, error=None):
        self.values = values or {"V1_I_18": 0.49, "V1_I_4": 115.66}
        self.error = error
        self.reads = 0
        self.closed = False

    def read(self, registers):
        self.reads += 1
        if self.error:
            raise self.error
        return dict(self.values)

    def close(self):
        self.closed = True


# ----- the profile ----------------------------------------------------------


def test_a_modbus_profile_names_its_registers_as_signals():
    profile = ms_profile()
    assert profile.is_modbus
    assert profile.signal_names == ["V1_I_18", "V1_I_4"]
    assert profile.signal_units["V1_I_4"] == "%"


def test_a_modbus_profile_round_trips_through_json(tmp_path):
    profile = ms_profile()
    profile.save(tmp_path / "ms.json")
    again = DeviceProfile.load(tmp_path / "ms.json")
    assert again.is_modbus and again.modbus["framing"] == "rtu_tcp"
    assert [r.address for r in again.registers] == [40000, 40002]


def test_a_sniffing_profile_is_unaffected():
    """The default stays what it was; existing profiles keep working."""
    profile = DeviceProfile(
        name="x", device_port=1210, request_framing=FramingSpec(mode="fixed", frame_len=6)
    )
    assert profile.source == SOURCE_SNIFF and not profile.is_modbus


def test_validation_checks_registers_not_signals():
    profile = ms_profile()
    assert profile.validate() == []
    profile.registers = []
    assert any("lists none" in p for p in profile.validate())


def test_a_bad_framing_is_named_with_the_vendor_wording():
    profile = ms_profile(framing="serial")
    assert any("RTU-TCP" in p for p in profile.validate())


def test_a_scale_of_zero_is_caught_for_registers():
    profile = ms_profile()
    profile.registers[0].scale = 0.0
    assert any("scale is 0" in p for p in profile.validate())


def test_duplicate_register_names_are_caught():
    profile = ms_profile()
    profile.registers[1].name = "V1_I_18"
    assert any("used 2 times" in p for p in profile.validate())


# ----- the monitor ----------------------------------------------------------


def monitor_with(profile, reader):
    monitor = DeviceMonitor(DeviceConfig(label="ms", ip="172.16.0.1", port=502))
    monitor.apply_profile(profile)
    monitor.reader = reader
    return monitor


def test_a_modbus_device_reads_rather_than_captures():
    monitor = monitor_with(ms_profile(), FakeReader())
    assert monitor.reads_registers
    assert monitor.decoder is None, "there are no replies to decode"


def test_polling_produces_samples_named_like_any_other_device():
    monitor = monitor_with(ms_profile(), FakeReader())
    result = monitor.poll()
    assert len(result.samples) == 1
    assert result.samples[0].values == {"V1_I_18": 0.49, "V1_I_4": 115.66}


def test_the_device_prefix_applies_to_register_names_too():
    monitor = monitor_with(ms_profile(), FakeReader())
    monitor.prefix = "ms."
    assert monitor.signal_names() == ["ms.V1_I_18", "ms.V1_I_4"]
    assert set(monitor.poll().samples[0].values) == {"ms.V1_I_18", "ms.V1_I_4"}


def test_polling_respects_the_configured_interval():
    """There is no point asking faster than the instrument updates."""
    import time

    monitor = monitor_with(ms_profile(poll_interval_s=60.0), FakeReader())
    monitor.poll()
    monitor.poll()
    monitor.poll()
    assert monitor.reader.reads == 1, "the interval should hold off the rest"


def test_a_failed_read_is_reported_and_does_not_raise():
    """An analyser restarting mid-run must not interrupt the oven's recording."""
    from lan_sniffer.readers.modbus import ModbusError

    monitor = monitor_with(ms_profile(), FakeReader(error=ModbusError("no reply")))
    result = monitor.poll()
    assert result.samples == []
    assert "no reply" in (monitor.last_error or "")
    assert "read failed" in monitor.status()


def test_a_modbus_device_produces_no_session_events():
    """It has no notion of a run, so it can never open or close a file."""
    monitor = monitor_with(ms_profile(), FakeReader())
    assert monitor.poll().events == []


def test_stopping_closes_the_connection():
    reader = FakeReader()
    monitor = monitor_with(ms_profile(), reader)
    monitor.stop_capture()
    assert reader.closed and monitor.reader is None


def test_changing_the_profile_drops_the_old_connection():
    reader = FakeReader()
    monitor = monitor_with(ms_profile(), reader)
    monitor.apply_profile(None)
    assert reader.closed


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
