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

Press **Add another device**. Each gets its own panel — name, address, adapter,
profile and its own setup buttons — and all of them stay visible, because
setting up a coupled rig means comparing two instruments, not remembering the
one a dropdown is hiding. Each is captured separately, so two instruments on
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

Each chunk in the `.raw.jsonl` records **which instrument sent it**, so one
file holding two devices can be taken apart again afterwards. A flow is
identified by the peer — the PC — which is the same for every device being
watched, so without this the two streams would be indistinguishable and get
decoded as one instrument.

A session can be started with **no profile on any device**. There is nothing to
put in a CSV column then, and the banner says `raw only` rather than reporting
zero rows — but every byte still lands in the `.raw.jsonl`, which is the whole
reason that file exists.

## Instruments that are read rather than watched

Some instruments compute in software what they display. A process mass
spectrometer streams detector data and derives concentrations from it, so the
numbers on screen may be assembled after the traffic rather than carried by it.
Whether that is true of a particular instrument is a question to settle by
searching, not by assuming — see *Finding values that don't look like values*
below, which exists because the first search here stopped a kilobyte into a
28 KB reply and reported the wrong answer.

Where the values genuinely are not on the wire, instruments like these usually
publish them another way. **Read over Modbus…** on a device's panel configures the app to ask the instrument's own
Modbus slave for its holding registers, which is how a process analyser is
normally wired into a plant control system. The values that come back are the
ones its software computed, exactly.

Enter the register map configured in the vendor software, then press **Test
read**. That check matters more than it looks: a wrong address, the wrong word
order or the wrong framing all return *numbers* rather than an error, so the
only real test is comparing them against the instrument's own display.

Three register formats are supported. Prefer **ieee754** — a 32-bit float across
two registers, needing nothing kept in sync. **single** stores one register
scaled between limits, and requires this app to hold an exact copy of those
limits; if they are ever changed on one side only, it returns wrong values with
no indication.

A device read this way needs no capture driver and no administrator rights, and
it still shares the session, the plot and the file with the sniffed ones.

### On connecting to an instrument

Everything else here is passive and never transmits, because the instruments it
was built for accept a single client and connecting would take it from the
software running the experiment. A Modbus slave exists to be polled and normally
accepts several, so reading one takes nothing away. The rule is kept where its
reason applies and deliberately not extended to an endpoint provisioned for data
output.

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

## Finding values that don't look like values

An instrument can be sending a reading without sending the *number*. It may hold
it in raw counts, scale it before display, or bury it in a spectrum where the
value is a band of indices the software integrates. Searching for the published
figure finds none of these, because none of them equals it.

`tools/find_values.py` searches for the relationship instead. Give it a capture
and the vendor software's own export of the same period:

```bash
python tools/find_values.py session.raw.jsonl questor.csv
```

The survey CSV works in place of the `.raw.jsonl` if that is what you kept.

For every column in the export it sweeps every byte offset and every encoding of
every channel, and every index of any array-shaped reply, looking for something
whose *shape over time* tracks the published column. It then fits a scale and
offset — and scores that fit on a stretch of the run it was **not** fitted on,
because a scale and offset can be made to match almost anything over the window
used to choose them.

It reports what it found and where, and says plainly when it found nothing. It
also says when a column never varied enough to be identifiable at all, which is
a different answer from *not present* and gets confused with it constantly.

Two limits used to make this search lie. The field sweep stopped after the first
kilobyte, so a 28 KB reply was 96% unread; and the survey CSV carried each
reply's full hex, which made a large-frame export unopenable. Both are fixed —
the sweep reaches much further, says how deep it went, and the CSV keeps the
first 512 bytes with the `.raw.jsonl` holding the rest.

A capture minutes long is worth far more than one seconds long here: a channel
that publishes every 8 seconds contributes two samples to a 20-second capture,
and nothing can be identified from two samples.

## Asking an instrument directly

`tools/probe_analyser.py` is the one thing here that transmits, and it exists
for the case where watching cannot work.

The MAX300 is that case. Four hours of its traffic, 58 channels, every offset
and encoding: nothing decodes into the ion-current range, and its two large
arrays correlate at **0.26 and −0.00 between sweeps 2.6 seconds apart**, so they
are detector noise rather than a repeatable spectrum. Questor computes the
published values and writes them to a file. No amount of sniffing that link
produces them — but nobody had asked the analyser itself.

Download **`probe-analyser.exe`** from
[Releases](https://github.com/OmerVered1/lan-signal-sniffer/releases) and run it
from a terminal on the machine wired to the instrument. It needs no Python, no
install and no capture driver, and the request lists are bundled inside it:

```bash
probe-analyser.exe list max300_requests
```

From a checkout it is the same tool, one word longer:

```bash
python tools/probe_analyser.py list probe_lists/max300_requests.json
```

`list` touches no network at all. The capture these requests came from is often
gigabytes and rarely lives on the machine wired to the instrument, so
`list --save requests.json` writes the few kilobytes that matter, and every
command takes that file — or the bare name of one bundled in the build — in
place of the capture.

`replay` sends each observed request once and shows
what comes back; `sweep` varies a single 32-bit field of one observed request
through an address range, which is how you find out whether the instrument holds
something its own software never asks for.

Three rules keep it honest:

* **Nothing is invented.** Every request sent is one the capture recorded, or
  one of those with a single field changed. The app never guesses at an opcode
  it has not seen the instrument accept.
* **Reads only, by evidence.** A request the vendor software repeated for hours
  is a poll. One sent once, at startup, may be a write, and is excluded unless
  named explicitly.
* **It refuses to open a socket** until you pass `--vendor-software-is-closed`.
  These instruments accept a single TCP client, and taking it from software
  that is mid-measurement is the thing this whole app was built to avoid.

That last rule is the trade being made. Passive capture is safe because it
cannot affect the instrument; this can, and is worth it only when the vendor
software is not running and there is no experiment to interrupt.

## When the instrument never sends the numbers

Sometimes the search comes back empty because the numbers were never on the
wire. The MAX300 in this rig is that case, settled twice over: no field in any
of its 58 channels decodes into the ion-current range, its detector arrays span
46 counts on a baseline of 8788 while Questor's own figures moved by 300–700×,
and the values reach Calisto through a **file** Questor writes rather than over
the network at all. No amount of sniffing recovers those.

The goal still works by another route. A session CSV carries capture-clock
timestamps and the vendor export carries its own, so where the clocks agree the
two can be joined on time: **File → Merge a vendor export into a session…**.
Pick the session, pick the export, give its columns a prefix, and it writes a
combined file.

Readings are matched to the nearest sample within 30 s, never interpolated —
these are measurements, and inventing values between two samples would put
numbers in the file that no instrument ever reported. Rows outside the export's
range are left blank rather than filled, and a merge that matches little says so.

Three export shapes are read, recognised by their contents rather than their
name — a Questor export arrives with no extension at all:

| Shape | What makes it awkward |
|---|---|
| **Questor5** | Tab-separated, one Time / Time Relative / Ion Current triple per species, with the species named on the row above the columns. |
| **Calisto** | UTF-16, a header block, then a fixed-width table whose only time column is elapsed seconds — absolute time exists solely as `Zone Start Time` in the header, and an export missing it is refused rather than placed at an assumed zero. |
| **Plain CSV** | Needs a column of absolute dates and times. Elapsed seconds alone cannot be lined up against a capture clock, and are refused rather than silently matching nothing. |

**The clock is derived, not typed.** Both vendors stamp in local time and a
session is stamped in UTC; a wrong shift does not fail, it pairs every reading
with the wrong row and reports that nothing matched. A session file is *named*
in local time and its rows are stamped in UTC, so the difference between the two
is the offset that was actually in force — daylight saving included. The app
works it out, shows it, and lets you overrule it.

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
on the bench.

`setaram_oven_calisto.json` was written from a 19.5-hour TPD capture and is the
worked example of what identification looks like when it goes well. Everything
Calisto plots arrives in the reply to the two-byte request `0008`: a 43-byte
frame holding the whole row as seven big-endian float32. One frame decoded to
`22.557554 / 22.730051 / 20287.716797 / 28.81 / 3.784194 / 20.023611 / 0.0`
against a Calisto row of `25.557554 / 22.730051 / …` — bit-exact on five of
seven, and replaying the whole run through the decoder gives **RMSE 0.16 °C** on
temperature, the residual being Calisto's own 3.3 s logging interval.

Two things about it are worth knowing, because both are traps:

* That channel answers in **two shapes** — a 6-byte "nothing new" ack and the
  full frame — and the ack is the more common of the two (29,723 against
  12,925). Anything that analyses only a channel's most common reply length
  keeps the acks and throws away every reading.
* `sample_temperature` carries `bias: 3.0` deliberately. The wire runs exactly
  3.000000 °C below what Calisto displays — a probe calibration applied inside
  Calisto — and the profile reproduces what Calisto shows, because that is the
  number the experiment is recorded against. Set the bias to 0.0 for the
  uncorrected probe. They hold no special status: they are the same kind of file the
wizard writes for any device, and the test suite checks that the generic scan
rediscovers the C80's channels on its own.

## Tests

```bash
python -m pytest tests/ -q
```

257 tests, no hardware and no capture driver needed — the decoding engine is pure
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
