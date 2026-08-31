"""What the window tells you at a glance.

These are not decoration. The app is meant to be left running beside an
experiment for hours, and everything here answers a question that previously
required opening a dialog or reading a line of packet counts: is this device
alive, what is it reading, and is any of it being written down.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt5.QtWidgets")
pytest.importorskip("pyqtgraph")

from lan_sniffer.monitor import DeviceConfig, DeviceMonitor  # noqa: E402
from lan_sniffer.ui.device_form import DeviceForm, _readable  # noqa: E402
from lan_sniffer.ui.main_window import _device_state  # noqa: E402
from lan_sniffer.ui.theme import banner_style, stylesheet  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    from PyQt5.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def monitor(**kwargs) -> DeviceMonitor:
    return DeviceMonitor(config=DeviceConfig(label="d", **kwargs))


# ----- what a device says about itself ---------------------------------------


def test_an_idle_device_says_so_rather_than_looking_broken():
    text, colour = _device_state(monitor(ip="1.2.3.4"), recording=False, capturing=False)
    assert text == "idle"
    assert colour == "#888888"


def test_a_problem_shows_the_problem_not_a_colour_alone():
    """Colour carries urgency; the words carry what to do about it."""
    m = monitor(ip="1.2.3.4")
    m.last_error = "HTTP 401 Unauthorized"
    text, colour = _device_state(m, recording=True, capturing=True)
    assert "401" in text
    assert colour == "#c0392b"


def test_each_kind_of_device_says_what_it_actually_does():
    watching, _ = _device_state(monitor(ip="1.2.3.4"), False, True)
    reading, _ = _device_state(monitor(questor_host="localhost"), False, True)
    assert watching == "watching traffic"
    assert reading == "reading Questor"


def test_a_device_with_no_columns_is_not_described_as_recording_them():
    """It contributes raw traffic and nothing else; saying otherwise overstates it."""
    text, _ = _device_state(monitor(ip="1.2.3.4"), recording=True, capturing=True)
    assert text.startswith("recording (raw only)")


def test_a_device_waiting_for_a_run_is_distinguishable_from_one_recording():
    from lan_sniffer.protocol.session import Calibration, SessionDetector

    m = monitor(ip="1.2.3.4")
    m.detector = SessionDetector(Calibration(mode="signature"))
    text, colour = _device_state(m, recording=False, capturing=True)
    assert "waiting for a run" in text
    assert colour == "#b7791f"


# ----- the numbers on the panel ----------------------------------------------


def test_a_reading_is_shown_at_a_readable_size():
    """Ion currents near 1e-7 and heat flow above 20,000 share this panel."""
    assert _readable(20287.716797) == "20,288"
    assert _readable(110.0687) == "110.069"
    assert _readable(3.03e-06) == "3.030e-06"
    assert _readable(0) == "0"


def test_the_value_panel_appears_only_once_there_is_something_in_it(qapp):
    form = DeviceForm(monitor(ip="1.2.3.4"))
    assert not form._readout.isVisibleTo(form)
    form.show_values({"d.temperature": 110.5}, {"d.temperature": "degC"})
    assert form._readout.isVisibleTo(form)
    assert "110.500" in form._readout.text()
    assert "degC" in form._readout.text()
    form.show_values({}, {})
    assert not form._readout.isVisibleTo(form)


def test_the_device_prefix_is_dropped_from_a_reading_on_its_own_panel(qapp):
    """It is already the panel's own device; repeating it wastes the width."""
    form = DeviceForm(monitor(ip="1.2.3.4"))
    form.show_values({"oven.sample_temperature": 110.5}, {})
    assert "sample_temperature" in form._readout.text()
    assert "oven.sample_temperature" not in form._readout.text()


# ----- the one-off actions ---------------------------------------------------


def test_the_actions_used_once_per_instrument_are_behind_a_menu(qapp):
    """Seven buttons per device competed with the two pressed during a run."""
    form = DeviceForm(monitor(ip="1.2.3.4"))
    assert form._setup.menu() is not None
    labels = [a.text() for a in form._setup.menu().actions() if a.text()]
    assert "Read from Questor…" in labels
    assert "Remove device" in labels


def test_a_menu_action_is_disabled_exactly_when_its_button_is(qapp):
    form = DeviceForm(monitor(ip="1.2.3.4"))
    form.set_enabled_for_capture(capturing=True, removable=True)
    for action, button in form._menu_actions:
        assert action.isEnabled() == button.isEnabled(), action.text()


# ----- the theme -------------------------------------------------------------


def test_the_dark_theme_is_a_stylesheet_and_the_light_one_is_nothing():
    assert "background" in stylesheet(True)
    assert stylesheet(False) == ""


def test_the_banner_stays_legible_in_both_themes():
    for dark in (True, False):
        recording = banner_style(dark, True)
        idle = banner_style(dark, False)
        assert recording != idle, "recording must not look like not recording"
        assert "background" in recording and "color" in recording


def test_a_reader_device_is_not_asked_for_settings_it_cannot_have(qapp):
    """It is addressed in its own dialog; four blank fields read as broken."""
    form = DeviceForm(monitor(questor_host="localhost"))
    form.show_relevant_fields()
    assert not form._interface.isVisibleTo(form)
    assert not form._port.isVisibleTo(form)
    assert not form._profile.isVisibleTo(form)
    assert not form._address.isVisibleTo(form)
    label = form._form.labelForField(form._address_row)
    assert label is not None and not label.isVisibleTo(form), (
        "the field hides but the word 'Address' stays, with nothing beside it"
    )


def test_a_sniffed_device_keeps_all_of_them(qapp):
    form = DeviceForm(monitor(ip="1.2.3.4"))
    form.show_relevant_fields()
    for widget in (form._interface, form._port, form._profile, form._address):
        assert widget.isVisibleTo(form)


def test_nothing_on_the_window_stays_light_when_the_theme_goes_dark(qapp):
    """A colour set in one place and forgotten in another is how this fails."""
    from lan_sniffer.ui.main_window import MainWindow

    w = MainWindow()
    try:
        w._apply_theme(True)
        for widget in (w._banner, w._session_label):
            style = widget.styleSheet()
            assert "#e8e8e8" not in style and "color:#555" not in style, style
        w._apply_theme(False)
        assert "#e8e8e8" in w._banner.styleSheet()
    finally:
        w.close()
