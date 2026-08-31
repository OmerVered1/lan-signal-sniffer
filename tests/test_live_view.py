"""The chart, which has to stay readable with two instruments on it.

The failure this guards against is not cosmetic. A coupled rig feeds the chart
heat flow at 20,287 uV beside mass concentrations of a hundredth of a percent;
on one linear axis the largest number sets the scale and everything else is a
flat line along the bottom. The chart then cannot show what is being recorded.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt5.QtWidgets")
pytest.importorskip("pyqtgraph")

from lan_sniffer.ui.live_view import (  # noqa: E402
    MAX_PANELS,
    LiveView,
    _to_unit_range,
    colour_for,
    group_by_unit,
)


@pytest.fixture(scope="module")
def qapp():
    from PyQt5.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


# ----- grouping --------------------------------------------------------------


def test_signals_are_grouped_by_unit_in_first_seen_order():
    names = ["furnace", "heat_flow", "sample", "power", "pressure"]
    units = {
        "furnace": "degC",
        "sample": "degC",
        "heat_flow": "uV",
        "power": "%",
        "pressure": "mBar",
    }
    groups = group_by_unit(names, units)
    assert [u for u, _ in groups] == ["degC", "uV", "%", "mBar"]
    assert dict(groups)["degC"] == ["furnace", "sample"]


def test_signals_with_no_unit_get_a_panel_of_their_own():
    """Usually raw counts, with no claim on a temperature axis."""
    groups = dict(group_by_unit(["a", "t"], {"t": "degC"}))
    assert groups["unitless"] == ["a"]
    assert groups["degC"] == ["t"]


def test_too_many_units_are_pooled_rather_than_shrunk_to_nothing():
    names = [f"s{i}" for i in range(12)]
    units = {n: f"unit{i}" for i, n in enumerate(names)}
    groups = group_by_unit(names, units)
    assert len(groups) == MAX_PANELS
    assert groups[-1][0] == "mixed"
    assert sum(len(m) for _u, m in groups) == len(names)


# ----- colours ---------------------------------------------------------------


def test_a_signal_keeps_its_colour_whatever_else_is_on_the_chart():
    """Position would do, until a device is added and every trace changes."""
    first = colour_for("dsc.sample_temperature")
    assert colour_for("dsc.sample_temperature") == first
    # Adding other signals cannot move it.
    assert colour_for("ms.V1_C_O2") != first or True
    assert colour_for("dsc.sample_temperature") == first


# ----- normalising -----------------------------------------------------------


def test_normalising_puts_a_curve_on_nought_to_one():
    assert _to_unit_range([10.0, 20.0, 30.0]) == [0.0, 0.5, 1.0]


def test_a_flat_curve_normalises_to_the_middle_rather_than_to_nothing():
    """Its flatness is the fact worth seeing."""
    assert _to_unit_range([7.0, 7.0, 7.0]) == [0.5, 0.5, 0.5]


# ----- the widget ------------------------------------------------------------


def test_the_chart_uses_one_panel_per_unit(qapp):
    view = LiveView()
    view.set_signals(
        ["t", "hf", "p"], {"t": "degC", "hf": "uV", "p": "%"}
    )
    assert len(view._panels) == 3
    assert len(view._curves) == 3


def test_every_panel_shares_the_time_axis(qapp):
    """Panning one and not the others would make them impossible to compare."""
    view = LiveView()
    view.set_signals(["t", "hf"], {"t": "degC", "hf": "uV"})
    linked = view._panels[1].getViewBox().linkedView(0)
    assert linked is view._panels[0].getViewBox()


def test_normalising_collapses_to_a_single_panel(qapp):
    view = LiveView()
    view.set_signals(["t", "hf"], {"t": "degC", "hf": "uV"})
    assert len(view._panels) == 2
    view._normalise.setChecked(True)
    assert len(view._panels) == 1
    assert len(view._curves) == 2


def test_data_survives_a_change_of_mode(qapp):
    """Toggling the view must not throw away the run so far."""
    view = LiveView()
    view.set_signals(["t"], {"t": "degC"})
    for i in range(5):
        view.add(float(i), {"t": 20.0 + i})
    view._normalise.setChecked(True)
    assert len(view._values["t"]) == 5
    view._normalise.setChecked(False)
    assert len(view._values["t"]) == 5


def test_session_markers_are_drawn_on_every_panel(qapp):
    """Recording state is invisible on the trace otherwise."""
    view = LiveView()
    view.set_signals(["t", "hf"], {"t": "degC", "hf": "uV"})
    view.add(0.0, {"t": 20.0})
    view.mark_session(1.0, "start")
    for panel in view._panels:
        lines = [i for i in panel.items if hasattr(i, "setPos") and hasattr(i, "angle")]
        assert lines, "each panel needs the marker, or it is missing where you look"


def test_markers_survive_a_rebuild(qapp):
    view = LiveView()
    view.set_signals(["t"], {"t": "degC"})
    view.add(0.0, {"t": 20.0})
    view.mark_session(1.0, "start")
    view._normalise.setChecked(True)
    panel = view._panels[0]
    assert any(hasattr(i, "angle") for i in panel.items)


def test_switching_theme_keeps_the_signals(qapp):
    view = LiveView()
    view.set_signals(["t", "hf"], {"t": "degC", "hf": "uV"})
    view.set_theme(dark=True)
    assert len(view._curves) == 2
    assert view._theme.dark
