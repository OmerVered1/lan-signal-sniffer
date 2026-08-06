"""Capture readiness must name the real problem, not guess at one.

These exist because of a shipped bug: the app imported `get_if_list` from
`scapy.arch.common`, where it does not live. The ImportError was swallowed by a
broad `except` that reported "no capture driver available" and told the user to
install Npcap — on a machine that already had Npcap, and on every other machine
too, because the import failed unconditionally.

Two things went wrong and both are covered here: the import target was wrong, and
the diagnosis blamed a component it had never actually checked.

scapy is not a test dependency, so a fake one is injected into sys.modules. That
also lets each failure mode be provoked deliberately, which real scapy cannot do.
"""

from __future__ import annotations

import sys
import types

import pytest

import lan_sniffer.capture.capture as capture


@pytest.fixture
def no_scapy(monkeypatch):
    """Make importing scapy fail, as on a machine where it is absent."""
    for name in list(sys.modules):
        if name == "scapy" or name.startswith("scapy."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == "scapy" or name.startswith("scapy."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)


def install_fake_scapy(monkeypatch, interfaces, where="scapy.interfaces"):
    """Inject a fake scapy exposing get_if_list only at `where`.

    The `where` argument is the point: it pins down which module the app reads
    the symbol from. Pointing it at the wrong module is exactly the shipped bug.
    """
    for name in list(sys.modules):
        if name == "scapy" or name.startswith("scapy."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    scapy = types.ModuleType("scapy")
    arch = types.ModuleType("scapy.arch")
    common = types.ModuleType("scapy.arch.common")
    ifaces = types.ModuleType("scapy.interfaces")
    scapy.arch = arch
    arch.common = common

    modules = {
        "scapy": scapy,
        "scapy.arch": arch,
        "scapy.arch.common": common,
        "scapy.interfaces": ifaces,
    }
    target = modules[where]
    target.get_if_list = lambda: list(interfaces)

    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


# ----- the shipped bug ------------------------------------------------------


def test_interfaces_are_found_where_scapy_actually_keeps_them(monkeypatch):
    # Regression: real scapy defines get_if_list in scapy.interfaces, and NOT
    # in scapy.arch.common. Reading it from the wrong module raised ImportError
    # on every platform, so capture was never available to anyone.
    install_fake_scapy(monkeypatch, ["eth0", "lo"], where="scapy.interfaces")
    assert capture.list_interfaces() == ["eth0", "lo"]


def test_platform_layer_is_initialised_before_interfaces_are_listed(monkeypatch):
    """scapy.interfaces returns nothing until scapy.arch has been imported.

    Second regression, found while fixing the first. `scapy.interfaces` holds
    `get_if_list`, but the list it reads is populated by the platform layer that
    `scapy.arch` sets up on import. Resolving the symbol from `scapy.interfaces`
    without importing `scapy.arch` yields a function that cheerfully returns an
    empty list on a machine with two dozen interfaces — no error, just a silently
    empty device dropdown.

    The fake below reproduces that lazy initialisation.
    """
    for name in list(sys.modules):
        if name == "scapy" or name.startswith("scapy."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    state = {"initialised": False}

    scapy = types.ModuleType("scapy")
    ifaces = types.ModuleType("scapy.interfaces")
    ifaces.get_if_list = lambda: ["eth0", "wlan0"] if state["initialised"] else []

    class ArchModule(types.ModuleType):
        def __getattr__(self, item):
            if item == "get_if_list":
                state["initialised"] = True
                return ifaces.get_if_list
            raise AttributeError(item)

    arch = ArchModule("scapy.arch")
    scapy.arch = arch
    scapy.interfaces = ifaces

    for name, module in (
        ("scapy", scapy),
        ("scapy.arch", arch),
        ("scapy.interfaces", ifaces),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    assert capture.list_interfaces() == ["eth0", "wlan0"], (
        "interfaces must be listed through the initialised platform layer"
    )


def test_readiness_is_ok_when_scapy_and_interfaces_are_present(monkeypatch):
    install_fake_scapy(monkeypatch, ["eth0"], where="scapy.interfaces")
    monkeypatch.setattr(capture, "_npcap_installed", lambda: True)
    state = capture.capture_readiness()
    assert state.ok, f"should be ready, got: {state.detail}"


def test_readiness_does_not_blame_npcap_when_scapy_is_missing(monkeypatch, no_scapy):
    # Telling someone to install a driver they already have, when the real
    # problem is a missing Python package, is what sent this investigation
    # down the wrong path in the first place.
    state = capture.capture_readiness()
    assert not state.ok
    assert "scapy" in state.detail.lower()
    assert "npcap" not in state.detail.lower()


# ----- honest diagnosis -----------------------------------------------------


def test_npcap_absence_is_reported_only_after_actually_checking(monkeypatch):
    install_fake_scapy(monkeypatch, [], where="scapy.interfaces")
    monkeypatch.setattr(capture.sys, "platform", "win32")
    monkeypatch.setattr(capture, "_npcap_installed", lambda: False)
    monkeypatch.setattr(capture, "_is_elevated", lambda: True)
    state = capture.capture_readiness()
    assert not state.ok
    assert "npcap" in state.detail.lower()
    assert "npcap.com" in state.remedy.lower()


def test_missing_elevation_is_not_reported_as_a_missing_driver(monkeypatch):
    # Npcap present, no interfaces, not elevated: the driver is fine and the
    # user needs to relaunch, not reinstall.
    install_fake_scapy(monkeypatch, [], where="scapy.interfaces")
    monkeypatch.setattr(capture.sys, "platform", "win32")
    monkeypatch.setattr(capture, "_npcap_installed", lambda: True)
    monkeypatch.setattr(capture, "_is_elevated", lambda: False)
    state = capture.capture_readiness()
    assert not state.ok
    assert "administrator" in state.remedy.lower()
    assert "install npcap" not in state.remedy.lower()


def test_npcap_present_and_elevated_but_no_interfaces_says_so_plainly(monkeypatch):
    install_fake_scapy(monkeypatch, [], where="scapy.interfaces")
    monkeypatch.setattr(capture.sys, "platform", "win32")
    monkeypatch.setattr(capture, "_npcap_installed", lambda: True)
    monkeypatch.setattr(capture, "_is_elevated", lambda: True)
    state = capture.capture_readiness()
    assert not state.ok
    # Nothing known is wrong, so it must not invent a cause.
    assert "no capture interfaces" in state.detail.lower()


def test_unix_missing_root_is_reported_as_such(monkeypatch):
    install_fake_scapy(monkeypatch, [], where="scapy.interfaces")
    monkeypatch.setattr(capture.sys, "platform", "darwin")
    monkeypatch.setattr(capture, "_is_elevated", lambda: False)
    state = capture.capture_readiness()
    assert not state.ok
    assert "sudo" in state.remedy.lower()
    assert "npcap" not in state.remedy.lower()


def test_visible_interfaces_without_elevation_are_flagged_not_promised(monkeypatch):
    # Listing interfaces needs fewer rights than opening one, so a green banner
    # can still be followed by a failure at Start capture. Say so up front.
    install_fake_scapy(monkeypatch, ["eth0"], where="scapy.interfaces")
    monkeypatch.setattr(capture, "_is_elevated", lambda: False)
    state = capture.capture_readiness()
    assert state.ok, "listing worked, so capture must not be blocked outright"
    assert state.warning
    assert "elevated" in state.warning.lower()


def test_no_warning_when_already_elevated(monkeypatch):
    install_fake_scapy(monkeypatch, ["eth0"], where="scapy.interfaces")
    monkeypatch.setattr(capture, "_is_elevated", lambda: True)
    state = capture.capture_readiness()
    assert state.ok and not state.warning


def test_readiness_never_raises(monkeypatch):
    # The banner is the app's way of explaining a broken environment; it must
    # not itself be the thing that crashes on one.
    install_fake_scapy(monkeypatch, [], where="scapy.interfaces")

    def explode():
        raise OSError("winpcap is not installed")

    sys.modules["scapy.interfaces"].get_if_list = explode
    state = capture.capture_readiness()
    assert not state.ok
    assert state.detail


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
