#!/usr/bin/env python3
"""A stand-in C80 that speaks the real protocol, for testing without hardware.

Answers the same frames the instrument does — a 6-byte request, and a reply that
echoes it and appends one big-endian float32 — so the app has to work out the
framing and find the field exactly as it would on the bench.

Like the real instrument, it accepts **one client at a time**. That is the
constraint the whole project exists for, and testing against a server that
happily accepts a second connection would quietly hide it.

    python tools/fake_instrument.py

Then point tools/fake_calisto.py at it, and sniff the conversation with the app.
"""

from __future__ import annotations

import argparse
import math
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 1210

# The command bytes the real C80 answers, from calorimeter_reader.py.
CMD_HEAT_FLOW = bytes.fromhex("0001000a0001")
CMD_SAMPLE_T = bytes.fromhex("000100080004")
CMD_EXTERNAL_T = bytes.fromhex("000100080005")

REQUEST_LEN = 6


def heat_flow(t: float) -> float:
    """A thermal wave like an Angstrom run: 300 mW with a 261 s oscillation."""
    return 300.0 + 50.0 * math.sin(2.0 * math.pi * t / 261.0)


def sample_temperature(t: float) -> float:
    """An isothermal hold at 150 C with a slow drift."""
    return 150.0 + 0.3 * (t / 3600.0) + 0.01 * math.sin(2.0 * math.pi * t / 37.0)


def external_temperature(t: float) -> float:
    return 24.5 + 0.2 * math.sin(2.0 * math.pi * t / 90.0)


CHANNELS = {
    CMD_HEAT_FLOW: heat_flow,
    CMD_SAMPLE_T: sample_temperature,
    CMD_EXTERNAL_T: external_temperature,
}


def serve(host: str, port: int, verbose: bool) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
    except OSError as e:
        print(f"could not bind {host}:{port} — {e}", file=sys.stderr, flush=True)
        if port < 1024:
            print("ports below 1024 need sudo", file=sys.stderr, flush=True)
        return 1
    listener.listen(1)
    print(f"fake instrument listening on {host}:{port} (one client at a time)", flush=True)
    print("channels: heat flow, sample temperature, external temperature", flush=True)

    started = time.time()
    while True:
        try:
            conn, peer = listener.accept()
        except KeyboardInterrupt:
            print("\nstopped", flush=True)
            return 0

        print(f"client connected from {peer[0]}:{peer[1]}", flush=True)
        replies = 0
        buffer = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                while len(buffer) >= REQUEST_LEN:
                    request, buffer = buffer[:REQUEST_LEN], buffer[REQUEST_LEN:]
                    channel = CHANNELS.get(request)
                    if channel is None:
                        # The real device ignores what it does not recognise.
                        if verbose:
                            print(f"  ignoring unknown request {request.hex()}", flush=True)
                        continue
                    value = channel(time.time() - started)
                    conn.sendall(request + struct.pack(">f", value))
                    replies += 1
                    if verbose:
                        print(f"  {request.hex()} -> {value:9.4f}", flush=True)
                    elif replies % 50 == 0:
                        print(f"  {replies} replies sent", flush=True)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except KeyboardInterrupt:
            conn.close()
            print("\nstopped", flush=True)
            return 0
        finally:
            conn.close()
        print(f"client disconnected after {replies} replies", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print every reply instead of a running count")
    args = parser.parse_args()
    return serve(args.host, args.port, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
