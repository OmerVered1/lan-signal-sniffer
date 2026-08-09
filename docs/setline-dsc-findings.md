# Setline DSC — what the traffic contains

Worked out from a capture taken 2026-08-09 (1908 s, 180 request channels)
cross-checked against Calisto's own export of the same run. Everything below is
evidence from that one session; where a claim is a guess it says so.

Device: Setaram Setline DSC, MAC `00:50:c2:30:d0:3b`, `169.254.93.1:1210`.
Same protocol family as the C80 — but, importantly, **not the same channels**.

## Confirmed

Both plotted quantities arrive in the reply to a single two-byte request,
`0008`, as a 23-byte packed status frame.

| Quantity | Request | Offset | Encoding | vs Calisto |
|---|---|---|---|---|
| Sample Temperature (°C) | `0008` | 15 | `f32be` | r = 0.999989, RMSE 0.044, max err 0.123 |
| HeatFlow (µV) | `0008` | 19 | `f32be` | r = 0.999957, RMSE 0.021, max err 0.068 |

Sweeping the frame byte by byte, offsets 15 and 19 are the only ones that decode
as plausible floats *and* track Calisto. Everything before offset 15 is header
and status: bytes 6–9 and 12–13 never change at all, and the rest take a handful
of distinct values.

`0008` is polled **only while a run is in progress**, which is convenient — it
cannot produce readings that belong to no experiment.

## Start and stop

Calisto controls a run by writing a value to one register. The frame layout is
`<hdr:2><cmd:2><arg:2>[payload]`, with `0004` marking a write where `0001`
marks a read.

| Command | Meaning | When, relative to Calisto's own run |
|---|---|---|
| `00040001000005` | **start** | t+21.2 s (run began t+20.0) |
| `00040001000002` | **stop** | t+922.4 s (run ended t+920.0) |
| `0004000100000c` | — | sent at *both* boundaries; not a discriminator |
| `00040001000018` | — | start side only, alongside `…05` |
| `00040001000019` | — | stop side only, alongside `…02` |

Each is sent **once**, which is why the profile sets `start_streak: 1`.

Two properties of this instrument break the assumptions the detector originally
made, and both are now handled:

- **Calisto polls continuously between runs.** Channels `ch0`–`ch13` run for the
  full 1908 s. A session that ends on a quiet timeout would therefore never end.
  Hence `stop_signatures`, and no timeout when one is present.
- **The control commands fire once, not repeatedly.** Requiring several
  sightings would mean a session never starts.

A separate, weaker signal exists as a fallback: four requests — `0008`,
`000100100001`, `00010010000a`, `00040011000100000000` — are polled only during
a run (t+24.6 → t+921.2). Slightly less precise than the control register, but
it brackets the run to within a few seconds.

## Not the signals, despite appearances

This device **answers the C80's own request bytes**, with values in entirely
plausible ranges:

| Request | Field | Range | vs Calisto |
|---|---|---|---|
| `000100080004` (C80 sample T) | `@6 f32be` | 25.63 … 37.78 | r = **0.73** |
| `0001000a0001` (C80 heat flow) | `@6 f32be` | −0.61 … 0.71 | r = **0.50** |

The ranges look right, which is exactly what makes this a trap. They are not
what Calisto plots. **The shipped C80 profile does not work on this instrument**
and must not be assumed to.

## The control loop

Calisto exports only two columns, so at first there was nothing to check the
other channels against. They identify each other instead: three of them satisfy
an exact algebraic relation.

    control_error  +  furnace_temperature  ==  programmed_setpoint

Residual over the whole run: **0.045 °C RMS, 0.09 °C worst case** — the width of
the values' own rounding. That single identity fixes all three at once, and it
settles which temperature is the furnace: the PID regulates
`000100020005` towards `000100100000`, so the regulated variable is by
definition the furnace, not merely a sensor that happens to read higher.

| Quantity | Request | Offset | Encoding | Evidence |
|---|---|---|---|---|
| Furnace / regulation temperature (°C) | `000100020005` | 6 | `f32be` | the regulated variable in the identity above; leads the sample by up to +4.7 K while heating, lags by −1.6 K while cooling |
| Programmed setpoint (°C) | `000100100000` | 6 | `f64be` | the identity's target; ramps 0 → 50 → 20, matching the programme |
| Control error (°C) | `000100020006` | 6 | `f32be` | setpoint − furnace, to 0.045 °C |
| Heater power (%) | `000100020004` | 6 | `f32be` | **exactly** 0.00 whenever the programme is cooling, 14–16 % while ramping; r = +0.94 with dT/dt |
| Heater power, averaged (%) | `000100020001` | 6 | `f32be` | same trace lagging the instantaneous one by ~60 s, r = 0.98 |

### ΔT and what heat flow actually is

ΔT is **not** a channel on the wire. Compute it:

    deltaT = furnace_temperature − sample_temperature

Over this run it ran **+4.7 K while heating and −1.6 K while cooling**. And the
exported heat flow is essentially that difference, scaled:

    HF(µV) = −0.9517 × deltaT − 0.2736        r = −0.9921

which is what a heat-flux DSC measures, so this is a consistency check rather
than a surprise. It also means heat flow and ΔT are not independent readings.

### Not an identity

`000100020000` sits at about **2 × the control error** for most of the run —
a proportional controller term — but the relation breaks down (residual 2.5 RMS,
50 worst case), so it is clamped or gated somewhere. Recorded as unexplained
rather than dressed up as a law.

## Other channels, uncorroborated

Correlations below are against Calisto's two exported signals. Nothing here is
confirmed — Calisto exports only two columns, so there is nothing to check the
rest against. Listed because they are the plausible places to look next.

| Channel | Request | Best field | Range | r\|T | r\|HF | Guess |
|---|---|---|---|---|---|---|
| ch8 | `000100020005` | `@6 f32be` | 25.42 … 51.31 | 0.96 | 0.10 | a second temperature — tracks the sample but reaches higher, so plausibly furnace or regulation |
| ch9 | `000100100000` | `@6 f64be` | 0 … 50 | 0.59 | 0.57 | programmed setpoint; the run's target was 50 °C |
| ch17 | `000100100001` | `@6 f64be` | 0 … 59.9 | 0.05 | 0.06 | counts **down** 56.6 → 0.65 — remaining time? |
| ch16 | `00010010000a` | `@5 i16le` | 10 … 1290 | 0.73 | 0.61 | rises monotonically — elapsed time |
| ch0 | `000100020004` | `@6 f32be` | 0 … 15.86 | 0.14 | 0.92 | tracks heat flow strongly; raw or unscaled |
| ch3 | `000100020001` | `@6 f32be` | 0 … 14.38 | 0.33 | 0.84 | same family |
| ch2, ch6 | `000100020000/6` | `@6 f32be` | −36.7 … 9.6 | ~0.35 | ~0.74 | same family |

`00010002000X` is evidently a bank of analogue channels, args `0000`–`0006`.
`00010010000X` looks like the programme/segment block. Confirming any of them
needs a run where Calisto is configured to export more than two columns.

## Reproducing this

```bash
python3 -m pytest tests/test_dsc_session.py -v
```

The capture itself is not in the repo — 8 MB of raw traffic — but the profile
`profiles/setaram_dsc_setline.json` encodes every conclusion above, and the
tests pin the behaviour that the findings required.
