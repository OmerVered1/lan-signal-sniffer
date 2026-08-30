#!/usr/bin/env python3
"""Ask an instrument what it will tell you, with its own software closed.

For the case where watching a link cannot work. The MAX300's published values
are computed in Questor and written to a file: nothing in four hours of its
traffic decodes into the ion-current range, and its large arrays correlate at
0.26 and -0.00 between sweeps 2.6 s apart, so they are detector noise rather
than a repeatable spectrum. Sniffing that link will not produce those numbers.
What has not been tried is asking the analyser directly.

This connects. Everything else in this app deliberately does not, because these
instruments accept one TCP client and taking it would interrupt a running
experiment. That reason does not apply when the vendor software is closed, and
this tool refuses to run until you confirm that it is.

    # what the capture shows the software asking for - no network at all
    python tools/probe_analyser.py list session.raw.jsonl --device 172.16.0.1

    # replay those same requests at the instrument
    python tools/probe_analyser.py replay session.raw.jsonl 172.16.0.1 30000 \
        --vendor-software-is-closed

    # sweep one field of one request through an address range
    python tools/probe_analyser.py sweep session.raw.jsonl 172.16.0.1 30000 \
        --request 4f000000060000000000000000000000000000000000000038000000 \
        --word 6 --range 0-255 --vendor-software-is-closed

Nothing is invented: every request sent is one seen in the capture, or one of
those with a single 32-bit field changed. Requests the software sent only once
are excluded by default, because a command that is not repeated may be a write.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lan_sniffer.readers.probe import (  # noqa: E402
    MIN_INTERVAL_S,
    ObservedRequest,
    Probe,
    observed_requests,
)
from lan_sniffer.writers.raw_writer import read_raw  # noqa: E402

CONFIRM = "--vendor-software-is-closed"


def load(args) -> list:
    chunks = list(read_raw(Path(args.capture)))
    found = observed_requests(chunks, args.device or "")
    if not args.include_one_offs:
        found = [r for r in found if r.is_poll]
    return found


def summarise(reply: bytes) -> str:
    if not reply:
        return "no reply"
    head = reply[:32].hex()
    tail = f" … ({len(reply)} bytes)" if len(reply) > 32 else f" ({len(reply)} bytes)"
    return head + tail


def cmd_list(args) -> int:
    found = load(args)
    print(f"{len(found)} distinct request(s) in {Path(args.capture).name}\n")
    by_opcode = {}
    for request in found:
        by_opcode.setdefault(request.opcode, []).append(request)
    for opcode in sorted(by_opcode):
        group = by_opcode[opcode]
        print(f"opcode 0x{opcode:02x} — {len(group)} request(s)")
        for request in group:
            print(f"  {request.describe()}")
            print(f"    {request.payload.hex()}")
        print()
    return 0


def _connected(args):
    if not args.vendor_software_is_closed:
        print(
            "Refusing to connect.\n\n"
            "This instrument accepts one TCP client. If its own software is "
            "running, connecting takes that client away from it and can "
            "interrupt a measurement in progress.\n\n"
            f"Close the vendor software, then pass {CONFIRM}.",
            file=sys.stderr,
        )
        return None
    print(f"connecting to {args.host}:{args.port} …")
    return Probe(args.host, args.port, timeout_s=args.timeout)


def cmd_replay(args) -> int:
    found = load(args)
    probe = _connected(args)
    if probe is None:
        return 2
    print(f"replaying {len(found)} request(s) the software was seen to send\n")
    answered = 0
    with probe:
        for request in found:
            reply = probe.ask(request.payload)
            mark = "ok " if reply.ok else "-- "
            answered += 1 if reply.ok else 0
            print(f"{mark}{request.payload.hex()[:48]:<48} {summarise(reply.reply)}")
            if reply.error:
                print(f"    {reply.error}")
            time.sleep(max(args.interval, MIN_INTERVAL_S))
    print(f"\n{answered} of {len(found)} answered.")
    print(
        "Compare a reply's size and contents against what the capture recorded "
        "for the same request: a different answer with the software closed is "
        "the interesting case."
    )
    return 0


def cmd_sweep(args) -> int:
    found = load(args)
    wanted = bytes.fromhex(args.request.replace(" ", ""))
    template = next((r for r in found if r.payload == wanted), None)
    if template is None:
        print(
            f"{args.request} is not a request this capture recorded.\n"
            "Only observed requests can be swept — run `list` to see them.",
            file=sys.stderr,
        )
        return 2

    low, _, high = args.range.partition("-")
    values = range(int(low), int(high or low) + 1)
    probe = _connected(args)
    if probe is None:
        return 2

    baseline = template.largest_reply
    print(
        f"sweeping word {args.word} of\n  {template.payload.hex()}\n"
        f"through {values.start}..{values.stop - 1}. "
        f"The capture's own answer to this request was {baseline} bytes.\n"
    )
    novel = 0
    with probe:
        for value in values:
            request = template.with_word(args.word, value)
            reply = probe.ask(request)
            if not reply.ok:
                continue
            flag = ""
            if len(reply.reply) != baseline:
                flag = "  <- different size from the observed reply"
                novel += 1
            print(f"  word={value:<6} 0x{value:02x}  {summarise(reply.reply)}{flag}")
            time.sleep(max(args.interval, MIN_INTERVAL_S))
    print(f"\n{novel} address(es) answered with something the capture never showed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, network: bool):
        p.add_argument("capture", help="a .raw.jsonl recorded from this instrument")
        if network:
            p.add_argument("host")
            p.add_argument("port", type=int)
            p.add_argument(CONFIRM, action="store_true",
                           help="confirm the instrument's own software is not running")
            p.add_argument("--timeout", type=float, default=3.0)
            p.add_argument("--interval", type=float, default=0.05,
                           help="seconds between requests")
        p.add_argument("--device", help="which instrument, when the capture holds two")
        p.add_argument("--include-one-offs", action="store_true",
                       help="also use requests sent only once — these may be writes")

    common(sub.add_parser("list", help="show the requests, without connecting"), False)
    common(sub.add_parser("replay", help="send each observed request once"), True)
    sweep = sub.add_parser("sweep", help="vary one field of one observed request")
    common(sweep, True)
    sweep.add_argument("--request", required=True, help="hex of the request to vary")
    sweep.add_argument("--word", type=int, required=True, help="which 32-bit field")
    sweep.add_argument("--range", default="0-255", help="e.g. 0-255")

    args = parser.parse_args()
    return {"list": cmd_list, "replay": cmd_replay, "sweep": cmd_sweep}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
