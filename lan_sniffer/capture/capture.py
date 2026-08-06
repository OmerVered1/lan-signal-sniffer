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
    """Whether this machine can capture, and what to do if it cannot."""

    ok: bool
    detail: str
    remedy: str = ""


def capture_readiness() -> Readiness:
    """Check that a capture backend is installed and usable."""
    try:
        import scapy  # noqa: F401
    except ImportError:
        return Readiness(
            ok=False,
            detail="scapy is not installed",
            remedy="pip install scapy",
        )

    try:
        from scapy.arch.common import get_if_list  # type: ignore

        interfaces = get_if_list()
    except Exception as e:  # pragma: no cover - depends on host networking
        if sys.platform == "win32":
            return Readiness(
                ok=False,
                detail=f"no capture driver available ({e})",
                remedy=(
                    "Install Npcap from https://npcap.com with "
                    "'WinPcap API-compatible mode' ticked, then run this app as "
                    "Administrator. Wireshark itself is not needed."
                ),
            )
        return Readiness(
            ok=False,
            detail=f"no capture interfaces available ({e})",
            remedy="On macOS and Linux, capture needs root: run with sudo.",
        )

    if not interfaces:
        return Readiness(
            ok=False,
            detail="no capture interfaces were found",
            remedy=(
                "Install Npcap (https://npcap.com) and run as Administrator."
                if sys.platform == "win32"
                else "Run with sudo so the BPF devices can be opened."
            ),
        )
    return Readiness(ok=True, detail=f"{len(interfaces)} capture interface(s) available")


def list_interfaces() -> List[str]:
    """Names of the interfaces that can be captured on."""
    try:
        from scapy.arch.common import get_if_list  # type: ignore

        return list(get_if_list())
    except Exception:  # pragma: no cover - depends on host networking
        return []


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
