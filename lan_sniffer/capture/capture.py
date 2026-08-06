# PASSIVE-ONLY MODULE
"""Live packet capture, feeding the reassembler.

This is the only module in the project that opens a network handle, and it opens
it for capture alone. Nothing here sends a packet, and nothing here connects to
the monitored device — the whole point of sniffing is that the vendor software
keeps its single allowed TCP connection while we watch. Adding a socket to a
device would defeat the design and could abort a running experiment.

Capture needs a kernel driver: Npcap on Windows, BPF devices on macOS and Linux.
That is unavoidable — it is the same engine Wireshark uses, and there is no way
to see another process's packets without it. What the app does remove is
Wireshark itself, tshark, hand-written display filters, and manual hex analysis.
`capture_readiness` checks the driver up front so a missing dependency surfaces
as an explained setup step rather than an empty graph.

scapy is imported lazily so the decoding engine, and its tests, run anywhere.
"""

from __future__ import annotations

import queue
import sys
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .reassembly import StreamChunk, TCPReassembler

# Bound on the hand-off queue. A poll loop produces a few packets per second, so
# reaching this means the consumer has stalled; dropping is better than growing
# without limit, and the drop is counted and surfaced.
MAX_QUEUED_PACKETS = 20000


@dataclass
class Readiness:
    """Whether this machine can capture, and what to do if it cannot.

    `warning` covers the case where capture is not blocked but is likely to
    fail anyway — listing interfaces needs fewer rights than opening them, so a
    green banner followed by a failure at Start capture is possible without it.
    """

    ok: bool
    detail: str
    remedy: str = ""
    warning: str = ""


def _get_if_list():
    """Return scapy's interface-listing function, from an initialised scapy.

    Two things have to be right here, and getting either wrong is quiet rather
    than loud.

    Where the symbol lives: `get_if_list` is defined in `scapy.interfaces` and
    re-exported from `scapy.arch`. It has never been in `scapy.arch.common`,
    which an earlier version of this module imported — that raised on every
    platform, and a broad `except` reported it as a missing capture driver, so
    the app told people to install Npcap they already had.

    When it works: the list it reads is populated by the platform layer that
    `scapy.arch` sets up on import. Resolving it from `scapy.interfaces` without
    that gives a function which returns an empty list on a machine with two
    dozen interfaces — no error at all, just an empty device dropdown. So
    `scapy.arch` is tried first, and `scapy.interfaces` only as a last resort.
    """
    last_error = None
    for module_name in ("scapy.arch", "scapy.all", "scapy.interfaces"):
        try:
            module = __import__(module_name, fromlist=["get_if_list"])
            return getattr(module, "get_if_list")
        except (ImportError, AttributeError) as e:
            last_error = e
    raise ImportError(
        f"scapy is installed but get_if_list could not be resolved from "
        f"scapy.arch, scapy.all or scapy.interfaces ({last_error})"
    )


def _is_elevated() -> bool:
    """True if the process has the rights packet capture needs."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os

        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX without win32
        return False


def _npcap_installed() -> bool:
    """Check for Npcap directly, rather than inferring it from a failure.

    Mirrors the check in windows_installer.iss. Npcap keeps wpcap.dll under
    System32\\Npcap, and installing it in the WinPcap-compatible mode this app
    needs also drops a copy directly in System32; the service key is the
    fallback for layouts that have differed between Npcap versions.
    """
    if sys.platform != "win32":
        return True  # not applicable; libpcap is part of the OS

    import os

    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    for path in (
        os.path.join(system32, "Npcap", "wpcap.dll"),
        os.path.join(system32, "wpcap.dll"),
    ):
        if os.path.exists(path):
            return True

    try:
        import winreg

        for root, key in (
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        ):
            try:
                with winreg.OpenKey(root, key):
                    return True
            except OSError:
                continue
    except ImportError:  # pragma: no cover - winreg is Windows-only
        pass
    return False


def capture_readiness() -> Readiness:
    """Report whether capture will work, and if not, why.

    Each failure gets its own answer. Four different causes used to collapse
    into "install Npcap", which is unhelpful when the driver is present and
    actively misleading when the real problem is something else.
    """
    try:
        import scapy  # noqa: F401
    except ImportError:
        return Readiness(
            ok=False,
            detail="scapy is not installed",
            remedy=(
                "Run: pip install scapy\n"
                "(Installed builds bundle it — seeing this in one means the "
                "build is broken.)"
            ),
        )

    try:
        interfaces = list(_get_if_list()())
    except Exception as e:
        if sys.platform == "win32" and not _npcap_installed():
            return Readiness(
                ok=False,
                detail="Npcap is not installed",
                remedy=(
                    "Install Npcap from https://npcap.com with 'WinPcap "
                    "API-compatible mode' ticked, then restart this app. "
                    "Wireshark itself is not needed."
                ),
            )
        return Readiness(
            ok=False,
            detail=f"could not list capture interfaces: {e}",
            remedy=(
                "Run this app as Administrator."
                if sys.platform == "win32"
                else "Capture needs root: run with sudo."
            ),
        )

    if interfaces:
        # Listing interfaces takes fewer rights than opening one for capture,
        # so this is not proof that capture will work. Flag it rather than
        # promise success and fail at Start capture.
        warning = ""
        if not _is_elevated():
            warning = (
                "Interfaces are visible, but capture also needs elevated "
                "rights — "
                + (
                    "restart as Administrator"
                    if sys.platform == "win32"
                    else "relaunch with sudo"
                )
                + " if starting the capture fails."
            )
        return Readiness(
            ok=True,
            detail=f"{len(interfaces)} capture interface(s) available",
            warning=warning,
        )

    # No interfaces. Say which of the possible causes actually applies.
    if sys.platform == "win32" and not _npcap_installed():
        return Readiness(
            ok=False,
            detail="Npcap is not installed",
            remedy=(
                "Install Npcap from https://npcap.com with 'WinPcap "
                "API-compatible mode' ticked, then restart this app."
            ),
        )
    if not _is_elevated():
        return Readiness(
            ok=False,
            detail="no capture interfaces are visible without elevated rights",
            remedy=(
                "Right-click the app and choose 'Run as administrator'."
                if sys.platform == "win32"
                else "Capture needs root: relaunch with sudo."
            ),
        )
    return Readiness(
        ok=False,
        detail="no capture interfaces were found",
        remedy=(
            "The capture driver is installed and this app is elevated, so this "
            "is unusual. Check that a network adapter is enabled."
        ),
    )


def list_interfaces() -> List[str]:
    """Names of the interfaces that can be captured on."""
    try:
        return list(_get_if_list()())
    except Exception:
        return []


@dataclass(frozen=True)
class InterfaceInfo:
    """One capture interface, described well enough to choose between them.

    A bare interface name is not something a user can pick from — on Windows
    they are adapter GUIDs, and even on Unix `en11` says nothing about which
    cable it is. The address is what identifies the right one, because the
    instrument's address is already known.
    """

    name: str
    description: str = ""
    ip: str = ""
    mac: str = ""

    def label(self) -> str:
        parts = [self.description or self.name]
        if self.ip:
            parts.append(f"— {self.ip}")
        return " ".join(parts)


def describe_interfaces() -> List[InterfaceInfo]:
    """List capture interfaces with their addresses, best-described first."""
    try:
        from scapy.interfaces import get_working_ifaces  # type: ignore

        import scapy.arch  # noqa: F401  (initialises the platform layer)

        found = []
        for iface in get_working_ifaces():
            found.append(
                InterfaceInfo(
                    name=str(getattr(iface, "name", "") or ""),
                    description=str(getattr(iface, "description", "") or ""),
                    ip=str(getattr(iface, "ip", "") or ""),
                    mac=str(getattr(iface, "mac", "") or ""),
                )
            )
        if found:
            # Interfaces holding an address are the plausible ones; the rest are
            # disabled or virtual adapters and belong at the bottom.
            found.sort(key=lambda i: (not i.ip, i.name))
            return found
    except Exception:
        pass
    return [InterfaceInfo(name=n) for n in list_interfaces()]


def _same_subnet(a: str, b: str) -> bool:
    """Rough test for two addresses being on the same link.

    Netmasks are not exposed consistently across platforms, so this compares
    prefixes: /16 for link-local, which is the actual APIPA block, and /24
    otherwise, which covers ordinary lab subnets.
    """
    pa, pb = a.split("."), b.split(".")
    if len(pa) != 4 or len(pb) != 4:
        return False
    if pa[0] == "169" and pa[1] == "254":
        return pb[0] == "169" and pb[1] == "254"
    return pa[:3] == pb[:3]


def interface_for(device_ip: str) -> Optional[str]:
    """Work out which interface can reach `device_ip`.

    Subnet matching comes first and the routing table second. An instrument on
    a direct cable self-assigns a 169.254.x.x address with no route to it, so
    the routing table answers with the default gateway — the internet-facing
    adapter, which is the one interface guaranteed not to see the instrument.
    Matching the address against each adapter's own address gets that right.
    """
    if not device_ip:
        return None

    for iface in describe_interfaces():
        if iface.ip and _same_subnet(device_ip, iface.ip):
            return iface.name

    try:
        from scapy.all import conf  # type: ignore

        if conf.route is not None:
            name = conf.route.route(device_ip)[0]
            if name:
                return str(name)
    except Exception:
        pass
    return None


class PacketPump:
    """Captures packets for one device and turns them into stream chunks.

    Runs the sniffer on its own thread and hands packets over through a bounded
    queue, so a slow consumer degrades into counted drops rather than unbounded
    memory growth. `poll` is called by the UI on a timer; keeping the Qt layer
    out of this class is what lets the whole pipeline be tested headlessly.
    """

    def __init__(
        self,
        device_ip: str,
        device_port: Optional[int] = None,
        interface: Optional[str] = None,
    ) -> None:
        self.device_ip = device_ip
        self.device_port = device_port
        self.interface = interface
        self._reassembler = TCPReassembler(device_ip)
        self._queue: "queue.Queue[tuple]" = queue.Queue(maxsize=MAX_QUEUED_PACKETS)
        self._sniffer = None
        self._lock = threading.Lock()
        self.packets_seen = 0
        self.packets_dropped = 0
        self.error: Optional[str] = None

    @property
    def bpf_filter(self) -> str:
        """Kernel-side filter, so idle CPU stays near zero."""
        parts = ["tcp", f"host {self.device_ip}"]
        if self.device_port:
            parts.append(f"port {self.device_port}")
        return " and ".join(parts)

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer  # type: ignore

        kwargs = dict(filter=self.bpf_filter, prn=self._on_packet, store=False)
        if self.interface:
            kwargs["iface"] = self.interface
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as e:  # pragma: no cover - teardown races
                self.error = f"stopping the capture failed: {e}"

    @property
    def running(self) -> bool:
        return self._sniffer is not None and getattr(self._sniffer, "running", False)

    # ----- capture thread -------------------------------------------------

    def _on_packet(self, packet) -> None:
        """Called on the sniffer thread. Extract fields and hand them over.

        Deliberately does almost nothing: scapy layers are not thread-safe to
        pass around, and any work here delays the next packet.
        """
        try:
            from scapy.layers.inet import IP, TCP  # type: ignore

            if IP not in packet or TCP not in packet:
                return
            ip, tcp = packet[IP], packet[TCP]
            flags = int(tcp.flags)
            item = (
                float(packet.time),
                ip.src,
                int(tcp.sport),
                ip.dst,
                int(tcp.dport),
                int(tcp.seq),
                bytes(tcp.payload),
                bool(flags & 0x02),  # SYN
                bool(flags & 0x01),  # FIN
                bool(flags & 0x04),  # RST
            )
        except Exception as e:  # pragma: no cover - malformed frames
            self.error = f"could not read a packet: {e}"
            return

        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self.packets_dropped += 1

    # ----- consumer -------------------------------------------------------

    def poll(self, limit: int = 5000) -> List[StreamChunk]:
        """Drain queued packets and return the stream chunks they completed."""
        chunks: List[StreamChunk] = []
        for _ in range(limit):
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            self.packets_seen += 1
            chunks.extend(self._reassembler.add_segment(*item))
        return chunks

    def status(self) -> str:
        parts = [f"{self.packets_seen} packets"]
        if self.packets_dropped:
            parts.append(f"{self.packets_dropped} dropped (consumer too slow)")
        if self.error:
            parts.append(self.error)
        return ", ".join(parts)


def replay_packets(
    device_ip: str, packets: List[Tuple], on_chunk: Optional[Callable] = None
) -> List[StreamChunk]:
    """Feed pre-extracted packet tuples through reassembly.

    Used to re-decode a saved capture without touching the network, which is how
    a session recorded under the wrong profile is recovered.
    """
    asm = TCPReassembler(device_ip)
    out: List[StreamChunk] = []
    for item in packets:
        for chunk in asm.add_segment(*item):
            out.append(chunk)
            if on_chunk is not None:
                on_chunk(chunk)
    return out
