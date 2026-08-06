# READ-ONLY MODULE
"""List the LAN devices this host has recently talked to, from the ARP cache.

This generalises `discover_calorimeter_ip` in
keithley-smu-control/calorimeter_reader.py, which looked up one known MAC. The
device picker needs the whole table instead, but the parsing is the part worth
keeping: it already handles Windows and Unix `arp` output, MAC addresses printed
with either separator and without zero padding, and the encoding surprises of a
non-English Windows console.

A device only appears here if something has spoken to it recently — which, for
this app, is exactly the situation of interest, since the vendor software is
running and polling.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

_MAC_RE = re.compile(r"[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Neighbor:
    """One entry from the host's ARP cache."""

    ip: str
    mac: str  # normalised to lower-case colon-separated form

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.ip}  ({self.mac})"


def normalise_mac(text: str) -> Optional[str]:
    """Canonicalise a MAC written with either separator and any padding."""
    try:
        parts = [int(x, 16) for x in re.split(r"[:-]", text.strip())]
    except ValueError:
        return None
    if len(parts) != 6 or any(not 0 <= p <= 0xFF for p in parts):
        return None
    return ":".join(f"{p:02x}" for p in parts)


def parse_arp_output(text: str) -> List[Neighbor]:
    """Pull (ip, mac) pairs out of `arp -a` / `arp -an` output.

    Kept separate from the subprocess call so it can be tested against captured
    output from platforms that are not the one running the tests.
    """
    found: List[Neighbor] = []
    seen = set()
    for line in text.splitlines():
        ip_match = _IP_RE.search(line)
        if not ip_match:
            continue
        mac = None
        for token in line.replace("(", " ").replace(")", " ").split():
            if _MAC_RE.fullmatch(token):
                mac = normalise_mac(token)
                if mac:
                    break
        if not mac or mac == "00:00:00:00:00:00":
            continue
        key = (ip_match.group(0), mac)
        if key in seen:
            continue
        seen.add(key)
        found.append(Neighbor(ip=ip_match.group(0), mac=mac))
    return found


def arp_neighbors(timeout: float = 3.0) -> Tuple[List[Neighbor], str]:
    """Read the OS ARP cache. Returns (neighbours, diagnostic).

    The diagnostic is empty on success and a specific, human-readable reason on
    failure — a device picker that just comes up empty is not actionable.
    """
    cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-an"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        return [], "arp is not on PATH"
    except subprocess.TimeoutExpired:
        return [], f"arp timed out after {timeout:.0f} s"
    except OSError as e:
        return [], f"arp failed to launch: {e}"

    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()[:120]
        return [], f"arp exited with code {proc.returncode}: {detail}"

    neighbors = parse_arp_output(proc.stdout or "")
    if not neighbors:
        return [], (
            "the ARP cache is empty — open the vendor software so it talks to "
            "the instrument, then refresh"
        )
    return neighbors, ""


def find_by_mac(mac: str, timeout: float = 3.0) -> Tuple[Optional[str], str]:
    """Look up a device's current IP by its fixed MAC."""
    target = normalise_mac(mac)
    if target is None:
        return None, f"not a MAC address: {mac!r}"
    neighbors, diagnostic = arp_neighbors(timeout=timeout)
    if diagnostic:
        return None, diagnostic
    for n in neighbors:
        if n.mac == target:
            return n.ip, ""
    return None, f"no device with MAC {target} in {len(neighbors)} ARP entries"
