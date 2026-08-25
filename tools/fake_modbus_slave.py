#!/usr/bin/env python3
"""A stand-in Modbus slave, for testing without the instrument.

Serves holding registers in the shapes Questor5 documents, so the reader can be
exercised end to end — framing, CRC, register planning and decoding — without
the mass spectrometer.

    python tools/fake_modbus_slave.py                # RTU over TCP, port 5020
    python tools/fake_modbus_slave.py --framing tcp  # standard Modbus TCP

By default it publishes seven values shaped like a TPD run: a helium carrier
near 115 and trace species that rise and fall as species desorb.
"""

from __future__ import annotations

import argparse
import math
import socket
import struct
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from lan_sniffer.readers.modbus import crc16  # noqa: E402

# name, base address, m/z-ish behaviour
CHANNELS = [
    ("V1_I_18", 40000, lambda t: 0.49 + 0.35 * math.exp(-((t - 300) ** 2) / 8000)),
    ("V1_I_2", 40002, lambda t: 0.11 + 0.9 * math.exp(-((t - 500) ** 2) / 6000)),
    ("V1_I_4", 40004, lambda t: 115.6 - 0.4 * math.sin(t / 120)),
    ("V1_I_32", 40006, lambda t: 0.267 + 0.02 * math.sin(t / 90)),
    ("V1_I_44", 40008, lambda t: 0.0024 + 0.02 * math.exp(-((t - 700) ** 2) / 5000)),
    ("V1_I_28", 40010, lambda t: 0.067 + 0.05 * math.sin(t / 70)),
    ("V1_I_40", 40012, lambda t: 0.037 + 0.01 * math.sin(t / 50)),
]


def registers_now(started: float) -> dict:
    """Current values, as IEEE 754 pairs in consecutive holding registers."""
    t = time.time() - started
    words = {}
    for _name, address, fn in CHANNELS:
        high, low = struct.unpack(">HH", struct.pack(">f", fn(t)))
        words[address] = high
        words[address + 1] = low
    return words


def serve(host: str, port: int, framing: str, verbose: bool) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
    except OSError as e:
        print(f"could not bind {host}:{port} — {e}", file=sys.stderr, flush=True)
        return 1
    listener.listen(4)
    print(f"fake Modbus slave on {host}:{port} ({framing})", flush=True)
    print("channels: " + ", ".join(f"{n}@{a}" for n, a, _ in CHANNELS), flush=True)
    started = time.time()

    while True:
        try:
            conn, peer = listener.accept()
        except KeyboardInterrupt:
            print("\nstopped", flush=True)
            return 0
        print(f"master connected from {peer[0]}:{peer[1]}", flush=True)
        try:
            while True:
                data = conn.recv(512)
                if not data:
                    break
                if framing == "tcp":
                    txid = struct.unpack(">H", data[:2])[0]
                    unit, function, address, count = struct.unpack(">BBHH", data[6:12])
                else:
                    txid = 0
                    unit, function, address, count = struct.unpack(">BBHH", data[:6])

                words = registers_now(started)
                payload = b"".join(
                    struct.pack(">H", words.get(address + i, 0)) for i in range(count)
                )
                body = bytes([unit, function, len(payload)]) + payload
                if framing == "tcp":
                    reply = struct.pack(">HHH", txid, 0, len(body)) + body
                else:
                    reply = body + struct.pack("<H", crc16(body))
                conn.sendall(reply)
                if verbose:
                    print(f"  read {count} regs from {address}", flush=True)
        except (ConnectionResetError, BrokenPipeError, struct.error):
            pass
        except KeyboardInterrupt:
            conn.close()
            print("\nstopped", flush=True)
            return 0
        finally:
            conn.close()
        print("master disconnected", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--framing", choices=("rtu_tcp", "tcp"), default="rtu_tcp")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    return serve(args.host, args.port, args.framing, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
