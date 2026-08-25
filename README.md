# LAN Signal Sniffer

Records the measurements a LAN instrument is reporting **while the vendor
software is running**, by watching the traffic rather than asking for it.

The companion tool in `keithley-smu-control/calorimeter_reader.py` polls a
Setaram calorimeter directly, and works — but only when Calisto is closed. The
instrument accepts one TCP client at a time, which that module reports as
*"port busy — is Calisto connected to this instrument?"*. This app inverts the
approach: it never connects to anything, so Calisto keeps its connection and an
experiment can be recorded as it actually runs.

It is **device-agnostic**. Point it at any LAN instrument, capture for a minute,
and it works out the frame boundaries, finds the numeric fields, and shows them
as ranked candidates with live traces. You name them and give them units; it
saves a profile and records CSV from then on.

---

## What it replaces

Wireshark, tshark, hand-written display filters, and staring at hex — the
workflow originally used to decode the C80. What it cannot replace is the
**kernel capture driver**: on Windows that means installing Npcap, because
seeing another process's packets is not something a program can do on its own.
Npcap installs standalone; Wireshark itself is not needed.

## Safety

The app is passive by construction and never transmits. No module opens a
connection to a monitored device — doing so would take the instrument's single
allowed TCP client away from the vendor software and could abort a running
experiment or an unattended temperature profile.

---

## Install

### Windows — the installer

Download **`LAN-Signal-Sniffer-Windows-Setup.exe`** from
[Releases](https://github.com/OmerVered1/lan-signal-sniffer/releases) and run it.
Python, PyQt5, pyqtgraph, numpy and scapy are all bundled — none of them need
installing.

**One thing is not bundled and cannot be: [Npcap](https://npcap.com).** It is a
kernel-mode driver with its own installer and licence, so it has to be installed
separately. Tick *WinPcap API-compatible mode*; Wireshark itself is not needed.
The installer checks for it and offers the download page if it is missing.

Then run the app **as Administrator** — capture does not work without it.

### macOS

Download `LAN-Signal-Sniffer-macOS.zip`, drag to Applications, and launch with
`sudo` so the BPF capture devices can be opened.

### From source

```bash
pip install -r requirements.txt
python main.py
```

If the capture driver is missing, the app opens anyway and says what to do
rather than showing an empty graph.

## Updates

*Help → Check for updates…* compares the running version against the latest
GitHub release and, if there is a newer one, downloads and launches the
installer. It also checks quietly at startup, so a new version surfaces without
being asked for.

An update is refused while a capture is running: the installer has to replace
files the running program holds open, and finding that out halfway through a
recording is worse than being told to stop first.

---

## Using it

**1. Pick the device.** *Refresh* lists everything in the host's ARP cache, so
the instrument appears once the vendor software has talked to it. Set the port
if you know it — it narrows the capture filter — or leave it on *any*.

**2. Start the capture, and let it watch.** A minute of normal polling is
plenty. Nothing is recorded yet.

**3. Identify signals.** The scan splits the traffic into channels, sweeps every
byte offset against every plausible encoding, and ranks what it finds. Each row
shows the evidence: the shape of the trace, the value range, where the bytes sit,
and a **Live** column that keeps updating while the dialog is open. Identifying a
signal is really a matching exercise — the instrument's own software is showing a
number on screen, and the question is which candidate tracks it — so watch the
live value rather than a frozen snapshot. Tick the real ones, name them, give
them units, and save. The name becomes the CSV column heading.

The ranking is a suggestion. Every accepted candidate carries the overlapping
readings it outranked, offered in the *Read from* dropdown, so a wrong pick is
one click to fix.

**4. Teach it idle versus running.** Record a couple of minutes with the
instrument idle, then a couple with an experiment going. The app compares them
and picks how to detect a run — a request only a run sends, a faster poll rate,
or neither. If neither, it says so plainly instead of shipping a detector that
fires at random; recording still works from the buttons.

**5. Leave it running.** Sessions open and close on their own, and *Start*,
*Stop* and *Split here* are always available.

## Watching two instruments at once

Press **Add** next to *Watching* to add a device. Each gets its own name, address,
adapter and profile, and each is captured separately — so two instruments on
different network adapters are fine.

Everything else is shared. Both devices plot on the same chart and record into
**one file**, which is the point: readings from two instruments in the same run
line up row by row without anything to reconcile afterwards.

Columns are prefixed with the device name — `dsc.sample_temperature`,
`c80.sample_temperature` — but **only when more than one device is configured**,
so a single-device recording keeps exactly the columns it always had and stays
comparable with older files.

### Which instrument decides when to record

In a coupled rig only one instrument actually has a run. A TPD setup is an oven
under Calisto with a mass spectrometer watching the evolved gas: the experiment
is the oven's, while the analyser polls continuously and has no notion of a run
at all.

So each device has a **Its experiment drives recording** tick. Leave it on for
the instrument running the experiment, and clear it for the ones just
contributing data — they will never open or close a file, whatever their traffic
does, but everything they report lands in the session while it is open.

With more than one controlling device the file opens on the first to start and
closes once all of them have stopped, since closing on the first would truncate
it while another was still going. The banner shows how many devices are live
(`1/2 devices`), and the device list marks each running one with a dot.

Devices **without a profile still have their raw traffic recorded** into the
session's `.raw.jsonl`, so an instrument you have not decoded yet is captured
alongside the run and can be decoded afterwards.

## When you can't identify it yourself

Some instruments will not give up their layout to a scan and a sparkline. For
those, **Record everything (no profile)** writes down every reading the scan
finds plausible — including the ones it ranked poorly — with wall-clock
timestamps and the untouched reply bytes alongside.

Stopping it produces two files: a wide CSV of the data, and a JSON describing
the channels, the framing, what each column means, and the config format to hand
back.

Give both to whoever is doing the identifying, **together with the instrument
software's own export of the same run**. That pairing is what makes it solvable:
lining the two up on the clock identifies which column is which quantity, and
shows where the experiment started. Neither is derivable from the bytes alone,
which is why the app does not pretend to know.

What comes back is a profile JSON. Load it with **Import profile…** — it is
validated on the way in, and refused with a specific list of problems if
anything is wrong, because most mistakes here decode to plausible-looking
numbers rather than failing outright.

## What a session produces

| File | Contents |
|---|---|
| `<device>_<timestamp>.csv` | One row per poll cycle, one column per named signal, with both an absolute and an elapsed timestamp. |
| `<device>_<timestamp>.raw.jsonl` | The reassembled traffic, so a session can be decoded again if a signal was identified wrongly. |

The absolute timestamp is the quiet win here. Sniffed samples carry the capture
clock, so a C80 file and a Keithley file line up directly — the clock offset
currently has to be re-derived from step events for every data set.

---

## How it works

```
packets → TCP reassembly → framing inference → field scan → profile → CSV
```

**Reassembly** keeps segment boundaries intact, because they are the framing
evidence. Byte patterns alone are ambiguous — a stream of 6-byte frames parses
just as cleanly into 3-byte or 2-byte ones — but a poll-and-wait client sends one
request per segment, and the capture records exactly where those fell.

**Framing** tries hypotheses in order of the evidence they need: printable text
split on a delimiter (SCPI/LXI), fixed-length frames, a length field in the
header (Modbus/TCP), then one-frame-per-segment as an honest fallback. Requests
are matched to replies by time — a reply is whatever arrived before the next
request — so the reply's structure never has to be known in advance.

**Field scanning** decodes every offset and encoding and asks how much each looks
like a measurement. Most readings disqualify themselves: a misaligned float32
view produces NaNs and values like 1e-38 within a few samples. What survives is
scored on smoothness, plausible magnitude, and resolution — how many distinct
values it takes, which is what separates a sensor from a status byte that is
trivially smooth because it barely moves. Counters and constants are kept but
never allowed to outrank a channel that genuinely moves.

Two tie-breakers are priors, not proofs, which is why alternatives stay visible:
instruments report physical quantities as IEEE floats far more often than scaled
integers, and for floats a wider reading beats a narrower one at the same offset,
since the narrow one is a fragment of it.

## Profiles

`profiles/*.json` — plain files, no code. `setaram_c80.json` and
`alexsys_drop.json` ship with their command bytes already filled in, carried
over from `keithley-smu-control/calorimeter_reader.py` where they were verified
on the bench. They hold no special status: they are the same kind of file the
wizard writes for any device, and the test suite checks that the generic scan
rediscovers the C80's channels on its own.

## Tests

```bash
python -m pytest tests/ -q
```

92 tests, no hardware and no capture driver needed — the decoding engine is pure
functions over byte streams. Synthetic fixtures cover all four protocol shapes
(C80-style fixed binary, Modbus/TCP with a transaction counter, SCPI text, and an
unprompted stream), and are built by pushing real segments through the real
reassembler so segment boundaries are produced the way a real client produces
them.

The load-bearing test is `test_c80_heat_flow_is_rediscovered_as_float32_be_at_offset_6`.
The C80's layout is the only ground truth available, and nothing in the scanner
knows about it — if the generic path finds heat flow and temperature unaided,
the approach holds for a device nobody has decoded yet.

## Layout

```
lan_sniffer/
  capture/    neighbours (ARP), live capture, TCP reassembly
  protocol/   framing, field scoring, profiles, session detection
  writers/    session CSV, raw sidecar
  ui/         main window, identify wizard, calibration, live plot
profiles/     device profiles (JSON)
tests/        synthetic fixtures and the full suite
```
