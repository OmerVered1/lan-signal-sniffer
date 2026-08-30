"""Merge a vendor software's own export into a recorded session.

Some instruments never put their published numbers on the wire. A process mass
spectrometer streams raw detector arrays and its software computes the
concentrations from them, so sniffing recovers the arrays and not the values —
no amount of scanning finds a number that was never transmitted.

The goal survives anyway. A session CSV already carries capture-clock
timestamps, and a vendor export carries its own; where the two clocks agree the
files can simply be joined on time. That produces the same combined table a
fully decoded device would have, for the instruments where decoding is not
available.

Vendor exports are joined by nearest timestamp rather than interpolated. These
are measurements, not a continuous function, and inventing values between two
samples of a mass spectrum would put numbers in the file that no instrument
ever reported.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Formats seen in the exports this has been used with. Tried in order.
TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S.%f",
    "%m/%d/%y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
)

from ..analysis.vendor import load_calisto, load_questor

# How far a vendor sample may sit from a session row and still be used. A
# process analyser reporting every 8 s should not have a reading stretched
# across a minute of oven data.
DEFAULT_TOLERANCE_S = 30.0


@dataclass
class MergeResult:
    path: Path
    rows: int = 0
    matched: int = 0
    added_columns: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        return self.matched / self.rows if self.rows else 0.0


def parse_timestamp(text: str) -> Optional[datetime]:
    text = text.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _sniff_rows(path: Path) -> Tuple[List[str], List[List[str]]]:
    """Read a CSV or tab-separated export, skipping any prose preamble.

    Vendor exports often carry a block of headings before the table, and are
    not always UTF-8 or comma separated.
    """
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        raise ValueError(f"{Path(path).name} is empty")

    lines = [ln for ln in text.splitlines() if ln.strip()]

    # Try each delimiter and keep whichever finds the widest consistent table.
    # Guessing from the first line does not work: an export that opens with
    # prose headings has no separator on that line at all, so a tab-separated
    # table behind a preamble would be read as a single column.
    def find_table(delimiter: str):
        for i, line in enumerate(lines[:-1]):
            width = len(line.split(delimiter))
            if width >= 2 and len(lines[i + 1].split(delimiter)) == width:
                return i, width
        return None, 0

    best = (None, 0, ",")
    for candidate in (",", "\t", ";"):
        start, width = find_table(candidate)
        if start is not None and width > best[1]:
            best = (start, width, candidate)
    start, _width, delimiter = best
    if start is None:
        raise ValueError(f"no table found in {Path(path).name}")

    reader = csv.reader(io.StringIO("\n".join(lines[start:])), delimiter=delimiter)
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        raise ValueError(f"no table found in {Path(path).name}")
    header = [c.strip() for c in rows[0]]
    return header, rows[1:]


def _timestamp_column(header: Sequence[str], rows: Sequence[Sequence[str]]) -> int:
    """Find which column holds a parsable timestamp."""
    for i, name in enumerate(header):
        if not rows:
            break
        sample = next((r[i] for r in rows[:20] if i < len(r) and r[i].strip()), "")
        if sample and parse_timestamp(sample) is not None:
            return i
    # Deliberately no fallback to a column merely *named* "time". Calisto's
    # export has a Time(s) column holding elapsed seconds, and accepting it
    # would drop every row on the floor while reporting success — the merge
    # joins on absolute time, so a file that never states one cannot be used.
    raise ValueError(
        "no timestamp column found: the export needs a column of absolute "
        "dates and times. A column of elapsed seconds cannot be lined up "
        "against a capture clock."
    )


def load_export(
    path: Path, tz_offset_hours: float = 0.0
) -> Tuple[List[str], List[Tuple[datetime, Dict[str, str]]]]:
    """Read a vendor export into (column names, [(utc time, values)]).

    Handles an ordinary CSV with a timestamp column, and the two shapes that
    are not ordinary CSVs at all but are what the instruments here actually
    write — a Questor5 export of species triples, and a Calisto export whose
    table has no absolute time in it. Both are recognised from their contents
    rather than their extension, since neither reliably has one.
    """
    kind = export_format(path)
    if kind == "questor":
        return load_questor(path, tz_offset_hours)
    if kind == "calisto":
        return load_calisto(path, tz_offset_hours)

    header, rows = _sniff_rows(path)
    ts_index = _timestamp_column(header, rows)
    columns = [n for i, n in enumerate(header) if i != ts_index]

    shift = timedelta(hours=tz_offset_hours)
    out: List[Tuple[datetime, Dict[str, str]]] = []
    for row in rows:
        if ts_index >= len(row):
            continue
        when = parse_timestamp(row[ts_index])
        if when is None:
            continue
        values = {
            header[i]: row[i].strip()
            for i in range(min(len(header), len(row)))
            if i != ts_index
        }
        out.append((when - shift, values))
    out.sort(key=lambda item: item[0])
    return columns, out


def export_format(path: Path) -> str:
    """Name the shape of an export: "questor", "calisto", or "csv".

    By inspection, because these files are not self-describing. A Questor
    export is tab-separated with a Time / Time Relative / Ion Current header;
    a Calisto export is UTF-16 with a Zone Start Time line above a fixed-width
    table. Anything else is treated as a plain CSV and has to carry its own
    absolute timestamps.
    """
    head = Path(path).read_bytes()[:4096]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = head.decode("utf-16", errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    if "Time Relative" in text or text.startswith("Sourcefile"):
        return "questor"
    if "Zone Start Time" in text:
        return "calisto"
    return "csv"


def session_clock_offset(session_csv: Path) -> Optional[float]:
    """Work out how far the local clock ran ahead of UTC during a session.

    A vendor export stamps in local time and a session in UTC, so the two have
    to be shifted onto each other before they can be joined. Getting that wrong
    does not fail — it pairs every reading with the wrong row, or with none —
    so it is derived rather than typed: a session file is *named* in local time
    and its rows are stamped in UTC, and the difference between the two is the
    offset that was actually in force, daylight saving included.

    Returns None when the name carries no timestamp or the file has no rows, in
    which case the caller has to ask.
    """
    session_csv = Path(session_csv)
    stamp = re.search(r"(\d{8})_(\d{6})", session_csv.stem)
    if not stamp:
        return None
    local = datetime.strptime(stamp.group(1) + stamp.group(2), "%Y%m%d%H%M%S")

    first: Optional[datetime] = None
    try:
        with session_csv.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                first = parse_timestamp(row.get("timestamp_utc", ""))
                if first is not None:
                    break
    except OSError:
        return None

    if first is None:
        # A session recorded with no profile has no rows, only a sidecar.
        sidecar = session_csv.parent / (session_csv.stem + ".raw.jsonl")
        try:
            with sidecar.open("r", encoding="utf-8") as handle:
                handle.readline()
                record = json.loads(handle.readline())
            first = datetime.fromtimestamp(float(record["ts"]), timezone.utc)
            first = first.replace(tzinfo=None)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None

    if first.tzinfo is not None:
        first = first.astimezone(timezone.utc).replace(tzinfo=None)
    # Quarter-hour resolution covers every real zone and rejects nothing.
    return round((local - first).total_seconds() / 900.0) * 0.25


def merge_into_session(
    session_csv: Path,
    export_csv: Path,
    output_csv: Path,
    prefix: str = "",
    tz_offset_hours: float = 0.0,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> MergeResult:
    """Add a vendor export's columns to a session, joined on the clock."""
    session_csv, export_csv, output_csv = map(Path, (session_csv, export_csv, output_csv))
    columns, samples = load_export(export_csv, tz_offset_hours)
    result = MergeResult(path=output_csv)
    if not samples:
        raise ValueError(f"no timestamped rows found in {export_csv.name}")

    qualified = [f"{prefix}{c}" for c in columns] if prefix else list(columns)
    result.added_columns = qualified
    times = [t for t, _v in samples]

    with session_csv.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        clash = set(qualified) & set(header)
        if clash:
            raise ValueError(
                "these column names already exist in the session; give the "
                "export a prefix: " + ", ".join(sorted(clash))
            )

        output_csv.parent.mkdir(parents=True, exist_ok=True)
        with output_csv.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(header + qualified)

            import bisect

            for row in reader:
                if not row:
                    continue
                result.rows += 1
                when = parse_timestamp(row[0])
                extra = [""] * len(qualified)
                if when is not None:
                    i = bisect.bisect_left(times, when)
                    best, gap = None, None
                    for j in (i - 1, i):
                        if 0 <= j < len(times):
                            d = abs((times[j] - when).total_seconds())
                            if gap is None or d < gap:
                                best, gap = j, d
                    if best is not None and gap is not None and gap <= tolerance_s:
                        values = samples[best][1]
                        extra = [values.get(c, "") for c in columns]
                        result.matched += 1
                writer.writerow(row + extra)

    if result.rows and result.coverage < 0.5:
        span = f"{times[0]} to {times[-1]} UTC"
        result.warnings.append(
            f"only {result.coverage:.0%} of session rows found a reading within "
            f"{tolerance_s:g} s. The export covers {span}; check that the two "
            "clocks agree and set a timezone offset if they do not."
        )
    return result
