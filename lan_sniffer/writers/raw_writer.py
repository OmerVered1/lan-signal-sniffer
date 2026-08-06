"""Save the raw reassembled traffic alongside every decoded session.

Decoding depends on a profile, and a profile can be wrong — a signal identified
against the wrong byte offset, a scale factor entered as 1 when it should have
been 0.1, a device whose firmware changed. Without the raw bytes the only way to
recover is to run the experiment again, which for a furnace run can mean a day
of instrument time. With them, the session is re-decoded in seconds.

The format is deliberately trivial and self-describing: a JSON header line, then
one record per chunk. It is not pcap — pcap would need link-layer framing that
was already discarded during reassembly — but it holds everything the decoding
engine consumes, which is what re-decoding actually needs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterable, Iterator, List, Optional

from ..capture.reassembly import FlowKey, StreamChunk

RAW_FORMAT = "lan-sniffer-raw"
RAW_VERSION = 1


@dataclass
class RawWriter:
    """Append reassembled chunks to a session sidecar file."""

    path: Path
    device_ip: str
    device_port: Optional[int] = None
    note: str = ""

    _handle: Optional[IO[str]] = None
    chunks_written: int = 0
    bytes_written: int = 0

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8")
        header = {
            "format": RAW_FORMAT,
            "version": RAW_VERSION,
            "device_ip": self.device_ip,
            "device_port": self.device_port,
            "note": self.note,
        }
        self._handle.write(json.dumps(header) + "\n")

    def add(self, chunks: Iterable[StreamChunk]) -> None:
        if self._handle is None:
            raise ValueError("raw writer is closed")
        for chunk in chunks:
            record = {
                "ts": chunk.ts,
                "dir": chunk.direction,
                "peer": f"{chunk.flow.peer_ip}:{chunk.flow.peer_port}",
                "dport": chunk.flow.device_port,
                "off": chunk.stream_offset,
                "data": chunk.data.hex(),
            }
            if chunk.gap_before:
                record["gap"] = chunk.gap_before
            self._handle.write(json.dumps(record) + "\n")
            self.chunks_written += 1
            self.bytes_written += len(chunk.data)
        self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "RawWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_raw(path: Path) -> Iterator[StreamChunk]:
    """Replay a sidecar file as stream chunks, ready to re-decode."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        first = handle.readline()
        try:
            header = json.loads(first)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path.name} is not a raw capture file") from e
        if header.get("format") != RAW_FORMAT:
            raise ValueError(f"{path.name} is not a raw capture file")
        if header.get("version", RAW_VERSION) > RAW_VERSION:
            raise ValueError(
                f"{path.name} was written by a newer version of the app "
                f"(v{header['version']} > v{RAW_VERSION})"
            )

        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            peer_ip, _, peer_port = record["peer"].rpartition(":")
            yield StreamChunk(
                ts=float(record["ts"]),
                flow=FlowKey(
                    peer_ip=peer_ip,
                    peer_port=int(peer_port),
                    device_port=int(record["dport"]),
                ),
                direction=record["dir"],
                data=bytes.fromhex(record["data"]),
                stream_offset=int(record["off"]),
                gap_before=int(record.get("gap", 0)),
            )


def read_raw_header(path: Path) -> dict:
    """Read just the header, to show what a sidecar holds without loading it."""
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.loads(handle.readline())
