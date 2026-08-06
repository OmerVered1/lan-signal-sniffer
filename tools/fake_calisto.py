#!/usr/bin/env python3
"""A stand-in for Calisto: connects to the instrument and polls it in a loop.

This is the process the app is meant to eavesdrop on. Run it against
tools/fake_instrument.py and sniff the conversation — nothing in the app knows
this is not the real thing.

It alternates between two states so the calibration wizard has something real to
compare:

    idle      polls the sample temperature only
    running   also polls heat flow, the way an experiment in progress would

That difference is exactly the "a run sends a request idle never sends" case the
detector looks for, so a full cycle exercises calibration and automatic session
start and stop.

    python tools/fake_calisto.py                  # 60 s idle, 120 s running, repeat
    python tools/fake_calisto.py --always-running # skip straight to a run
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

CMD_HEAT_FLOW = bytes.fromhex("0001000a0001")
CMD_SAMPLE_T = bytes.fromhex("000100080004")
REPLY_LEN = 10


def read_reply(sock: socket.socket) -> float:
    buffer = b""
    while len(buffer) < REPLY_LEN:
        chunk = sock.recv(REPLY_LEN - len(buffer))
        if not chunk:
            raise ConnectionError("instrument closed the connection")
        buffer += chunk
    return struct.unpack(">f", buffer[6:10])[0]


def poll_loop(
    host: str,
    port: int,
    interval: float,
    idle_seconds: float,
    run_seconds: float,
    always_running: bool,
) -> int:
    try:
        sock = socket.create_connection((host, port), timeout=5.0)
    except OSError as e:
        print(f"could not connect to {host}:{port} — {e}", file=sys.stderr, flush=True)
        print("is tools/fake_instrument.py running?", file=sys.stderr, flush=True)
        return 1

    print(f"connected to {host}:{port}", flush=True)
    running = always_running
    phase_started = time.time()
    if always_running:
        print(">>> EXPERIMENT RUNNING (polling heat flow and temperature)", flush=True)
    else:
        print("--- idle (polling temperature only)", flush=True)

    try:
        while True:
            now = time.time()
            if not always_running:
                elapsed = now - phase_started
                if running and elapsed >= run_seconds:
                    running = False
                    phase_started = now
                    print("--- idle (polling temperature only)", flush=True)
                elif not running and elapsed >= idle_seconds:
                    running = True
                    phase_started = now
                    print(">>> EXPERIMENT RUNNING (polling heat flow and temperature)", flush=True)

            requests = [CMD_SAMPLE_T]
            if running:
                # Heat flow first, the way the real polling rotation runs.
                requests.insert(0, CMD_HEAT_FLOW)

            readings = []
            for request in requests:
                sock.sendall(request)
                readings.append(read_reply(sock))

            label = "RUN " if running else "idle"
            print(f"  {label} " + "  ".join(f"{v:9.4f}" for v in readings), flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
        return 0
    except (ConnectionError, OSError) as e:
        print(f"connection lost: {e}", file=sys.stderr, flush=True)
        return 1
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1210)
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between poll cycles (default 1)")
    parser.add_argument("--idle-seconds", type=float, default=60.0)
    parser.add_argument("--run-seconds", type=float, default=120.0)
    parser.add_argument("--always-running", action="store_true",
                        help="never go idle — useful for a quick decode check")
    args = parser.parse_args()
    return poll_loop(
        args.host,
        args.port,
        args.interval,
        args.idle_seconds,
        args.run_seconds,
        args.always_running,
    )


if __name__ == "__main__":
    raise SystemExit(main())
