#!/usr/bin/env python3
"""Search a capture for the values a vendor's software publishes.

For an instrument whose numbers do not obviously appear on the wire. Give it a
recorded capture and the software's own export of the same period, and it looks
for anything in the traffic that tracks each published column — a plain field,
or a band of indices inside a larger array.

    python tools/find_values.py session.raw.jsonl questor.csv

Correlation, not equality: a reading held in counts, or scaled before display,
never equals the published number but follows it exactly. Every fit is scored
on a stretch of the run it was not fitted on, so a scale and offset chosen to
match one window cannot flatter itself.

It will say when it finds nothing, and when a column never moved enough to be
identifiable at all.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lan_sniffer.analysis.reconstruct import analyse, channels_from_survey  # noqa: E402
from lan_sniffer.writers.merge import load_export  # noqa: E402
from lan_sniffer.writers.raw_writer import read_raw  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "capture",
        help="a .raw.jsonl, or the survey CSV from Record everything",
    )
    parser.add_argument("export", help="the vendor software's own CSV export")
    parser.add_argument(
        "--tz-offset", type=float, default=0.0,
        help="hours to subtract from the export's stamps if its clock is local",
    )
    parser.add_argument(
        "--tolerance", type=float, default=15.0,
        help="seconds a reading may sit from a frame and still be paired",
    )
    parser.add_argument("--column", action="append", help="limit to one column")
    parser.add_argument(
        "--device",
        help="with two instruments in one capture, search only this one (by IP)",
    )
    args = parser.parse_args()

    source = Path(args.capture)
    if source.name.endswith(".raw.jsonl"):
        chunks = list(read_raw(source))
        replies = None
        print(f"capture: {len(chunks)} chunks")
    else:
        chunks = []
        replies = channels_from_survey(source)
        total = sum(len(v) for v in replies.values())
        print(f"capture: {len(replies)} channels, {total} replies (from the CSV)")
    if args.device and replies is not None:
        replies = {k: v for k, v in replies.items() if k.startswith(args.device + "/")}
    elif args.device:
        chunks = [c for c in chunks if c.device_ip == args.device]
        if not chunks:
            print(f"no traffic in this capture came from {args.device}")
            return 1

    columns, samples = load_export(Path(args.export), args.tz_offset)
    wanted = args.column or columns
    print(f"export : {len(samples)} rows, columns {', '.join(columns)}")
    if samples:
        print(f"         {samples[0][0]} to {samples[-1][0]}")
    print()

    report = analyse(
        chunks, samples, wanted, tolerance_s=args.tolerance, replies=replies
    )
    for note in report.notes:
        print(f"  note: {note}")
    if report.notes:
        print()

    print(f"{len(report.arrays)} array view(s) considered")
    print()
    for fit in report.scalars + report.bands:
        mark = "FOUND   " if fit.convincing else "weak    "
        print(f"  {mark}{fit.describe()}")
        # A wildly negative r2 means the fitted line misses the held-out half
        # by orders of magnitude; the exact figure carries nothing further.
        r2 = f"{fit.r2_holdout:.4f}" if fit.r2_holdout > -10 else "far below zero"
        print(f"          held-out r={fit.r_holdout:+.4f} r2={r2} "
              f"over {fit.samples} paired samples")
    if not (report.scalars or report.bands):
        print("  nothing in the capture tracked any of the columns.")
    print()

    if report.solved:
        print("Reproducible from the capture: " + ", ".join(report.solved))
    else:
        print(
            "No column was reproduced convincingly. Either the values are not\n"
            "in this capture, or the run did not vary enough to identify them."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
