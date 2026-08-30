#!/usr/bin/env python3
"""Cut a smaller capture out of a long one, by device and by time.

A TPD run is a working day long and the sidecar comes out in gigabytes, most of
it one instrument's bulk replies. Analysis does not need all of it: what it
needs is a stretch where the published values actually moved, from one
instrument at a time.

    python tools/slice_capture.py big.raw.jsonl out.raw.jsonl \
        --device 169.254.60.1 --from-epoch 1787857450 --seconds 7200

Streams line by line — the input is never held in memory — and rewrites the
header so the result is an ordinary capture file that every other tool reads.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--device", help="keep only this instrument's traffic")
    parser.add_argument("--from-epoch", type=float, help="start of the window")
    parser.add_argument("--seconds", type=float, help="length of the window")
    parser.add_argument(
        "--max-payload", type=int,
        help="skip replies longer than this, to thin out bulk transfers",
    )
    args = parser.parse_args()

    begin = args.from_epoch
    end = begin + args.seconds if (begin is not None and args.seconds) else None

    kept = skipped = 0
    first = last = None
    with open(args.source, "rb") as src, open(args.destination, "wb") as dst:
        header = json.loads(src.readline())
        header["note"] = (
            f"sliced from {Path(args.source).name}"
            + (f", device {args.device}" if args.device else "")
        )
        if args.device:
            header["device_ip"] = args.device
        dst.write(json.dumps(header).encode() + b"\n")

        for line in src:
            # Parsed by hand rather than with json.loads: at ten million lines
            # the difference is minutes, and only two fields are needed to
            # decide whether a record is wanted at all.
            i = line.find(b'"ts": ')
            if i < 0:
                continue
            ts = float(line[i + 6 : line.find(b",", i)])
            if begin is not None and ts < begin:
                continue
            if end is not None and ts > end:
                # Records are written in capture order, so nothing later can
                # fall inside the window.
                break
            if args.device:
                j = line.find(b'"dev": "')
                if j < 0 or line[j + 8 : line.find(b'"', j + 8)].decode() != args.device:
                    skipped += 1
                    continue
            if args.max_payload:
                j = line.find(b'"data": "')
                if j >= 0 and (line.find(b'"', j + 9) - j - 9) // 2 > args.max_payload:
                    skipped += 1
                    continue
            dst.write(line)
            kept += 1
            first = ts if first is None else first
            last = ts

    print(f"kept {kept:,} records, skipped {skipped:,}")
    if first is not None:
        show = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")
        print(f"window {show(first)} to {show(last)} UTC ({(last - first) / 60:.1f} min)")
        print(f"wrote {Path(args.destination).stat().st_size / 1e6:.1f} MB")
    else:
        print("nothing matched — check the device address and the time window")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
