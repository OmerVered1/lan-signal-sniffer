# Testing

Three levels, in the order worth doing them. The first two need no instrument
and no lab — do them on your own machine before carrying anything to the bench.

---

## Level 1 — the test suite (30 seconds, no setup)

```bash
python3 -m pytest tests/ -q
```

92 tests, none of which need hardware, a capture driver, or even scapy. The
decode engine is pure functions over byte streams, so everything from TCP
reassembly to CSV output is covered here.

Worth knowing what it actually proves. The synthetic captures are built by
pushing real TCP segments through the real reassembler — not by handing the
framer a tidy byte string — so segment boundaries are produced the way a real
client produces them. Four protocol shapes are covered: C80-style fixed binary,
Modbus/TCP with a transaction counter, SCPI text, and an unprompted stream.

The one to look at if you only look at one:

```bash
python3 -m pytest tests/test_fields.py -v -k c80
```

Nothing in the scanner knows anything about the C80. If it independently finds
heat flow and temperature as big-endian float32 at offset 6 — which is what was
originally worked out by hand from a Wireshark capture — then the generic path
works on a device nobody has decoded.

To see the ranking rather than a pass/fail:

```bash
PYTHONPATH=.:tests python3 -c "
import synth
from lan_sniffer.protocol.framer import analyze_flow, group_chunks_by_flow
from lan_sniffer.protocol.fields import scan_channel
r = analyze_flow(next(iter(group_chunks_by_flow(synth.c80_capture()).values())))
for ch in r.channels:
    print(ch.signature_hex, '->', end=' ')
    c = scan_channel(ch.payloads).candidates[0]
    print(c.describe(), '%.3f' % c.score, '%.2f..%.2f' % (c.minimum, c.maximum))
"
```

---

## Level 2 — a fake C80 on your own Mac (10 minutes)

This is the important one, because it exercises the **live capture path** that
the test suite deliberately cannot: real packets, real kernel filter, real
reassembly, into the real GUI.

`tools/fake_instrument.py` speaks the actual C80 protocol and, like the real
instrument, accepts **one client at a time**. `tools/fake_calisto.py` is the
process you are eavesdropping on. Nothing in the app knows they are not real.

### One-time setup

```bash
pip3 install --user scapy
```

On macOS capture needs root, so the app runs under `sudo`.

### Run it

Three terminals.

**Terminal 1 — the instrument:**

```bash
python3 tools/fake_instrument.py -v
```

**Terminal 2 — the vendor software:**

```bash
python3 tools/fake_calisto.py
```

It alternates: 60 s idle (temperature only), then 120 s running (temperature and
heat flow), and repeats. That difference is exactly the "a run sends a request
idle never sends" case, so one full cycle exercises calibration and automatic
session start and stop.

**Terminal 3 — the app:**

```bash
sudo python3 main.py
```

### What to check, in order

1. **It cannot connect.** In Terminal 2, notice `fake_calisto` holds the only
   connection. This is the constraint the project exists for.
2. **Set up the capture.** Interface `lo0`, address `127.0.0.1`, port `1210`.
   Press *Start capture*. The status bar should start counting packets.
3. **Identify signals.** Wait about a minute, then *Identify signals…*. You
   should see two channels, each with `byte 6, f32be` at the top, scoring around
   0.95 with everything else far below. Name them `heat_flow` (mW) and
   `sample_temperature` (degC), and save.
4. **Watch it decode.** The live plot should show heat flow oscillating around
   300 mW and temperature sitting near 150 °C. Cross-check against the numbers
   Terminal 1 is printing — they must match to the digit.
5. **Calibrate.** *Teach idle vs running…*. Record the idle leg while Terminal 2
   says `--- idle`, then the running leg while it says `>>> EXPERIMENT RUNNING`.
   It should report **signature** detection and name the heat-flow request as
   the trigger.
6. **Leave it alone.** Sessions should now open and close on their own as
   Terminal 2 cycles. Check the CSVs in `~/LAN Sniffer Sessions/`.

### If the interface list is empty or capture fails

That means the capture driver is not reachable — on macOS, almost always that
you did not use `sudo`. The app says so in the banner rather than showing an
empty graph.

---

## Level 3 — the real instrument (in the lab)

Everything above runs on the lab PC unchanged, with three differences: install
[Npcap](https://npcap.com) with *WinPcap API-compatible mode* ticked (Wireshark
itself is not needed), run the app **as Administrator**, and select the real
instrument from *Refresh* rather than typing `127.0.0.1`.

The C80 profile already ships with its command bytes filled in, so you can skip
identification and go straight to recording — but running identification anyway
is a better test, because it proves the generic path works on your actual
instrument rather than on a fixture I wrote.

Four things to confirm, and the third is the one that matters to your professor:

1. **The generic scan finds the right fields.** Identify from scratch and check
   it lands on `byte 6, f32be` for both channels.
2. **The numbers are right.** Record a session alongside a normal Calisto run and
   compare the sniffed CSV against Calisto's own export. Values must match
   sample for sample — not approximately.
3. **Calisto is undisturbed.** Run a full experiment with the sniffer active and
   confirm Calisto logs no communication errors and no dropped samples. This is
   the claim the whole approach rests on: capture is passive, so there should be
   nothing to see.
4. **Session detection fires correctly.** Start and stop an experiment and check
   the session boundaries land where they should. This is the one genuinely
   unknown: if Calisto polls continuously even when idle, calibration will say so
   and fall back to the manual buttons. That is a real possible outcome, not a
   failure of the app.

### Also worth doing once

Compare a sniffed session against a `calorimeter_reader.py` run taken with
Calisto **closed**. Same instrument, same channels, two completely independent
paths to the same numbers.

---

## What is not yet verified

Being straight about the gaps:

- **The live capture path has never run against scapy on this machine**, because
  scapy is not installed here. Levels 2 and 3 are the first real exercise of it.
- **Nothing has touched the real instrument.** Every number in the test suite
  comes from a fixture I wrote, which means the tests prove the engine is
  self-consistent — not that it reads your C80 correctly. Level 3 step 2 is what
  establishes that.
- **Whether Calisto polls while idle is unknown**, so whether automatic session
  detection is possible at all is still an open question that only the bench can
  answer.
