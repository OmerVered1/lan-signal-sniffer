# READ-ONLY MODULE
"""Read the exports instrument software writes, onto the capture's clock.

Every identification here is a comparison against what the vendor's own software
displayed, so these files are the ground truth and reading them wrongly is the
one mistake that cannot be caught later — a misread export produces a confident
fit to nothing.

Two things about them are worth stating plainly:

**They stamp in local time.** The capture clock is epoch seconds, so an export
has to be shifted onto it, and a wrong shift does not fail — it silently pairs
each reading with the wrong frame and reports that nothing matches. The offset
is a parameter with no default guess for that reason, and `local_offset_hours`
derives it from a session filename, which is written in local time while the
first record inside is epoch.

**Calisto's export carries no absolute stamps in its table.** It has a
`Time(s)` column counting from zero, and a `Zone Start Time` line in the header.
The two together give absolute time; either alone does not.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

Sample = Tuple[datetime, Dict[str, str]]

# Columns that hold a clock rather than a measurement, and would otherwise be
# offered to a correlation search as though they were readings.
_TIME_COLUMNS = ("time", "time relative [s]", "index", "time(s)")


def _is_time_column(name: str) -> bool:
    """A clock is not a measurement, and correlates with everything that ramps.

    Left in, it comes back as a confident match on whichever channel counts
    upward, and reads as a success. Duplicate columns carry a `#2` suffix, so
    the suffix is stripped before comparing.
    """
    bare = re.sub(r"\s*#\d+$", "", name).strip().lower()
    return bare in _TIME_COLUMNS


def _text(path: Path) -> str:
    """Decode an export, whatever the vendor chose to write it in."""
    raw = Path(path).read_bytes()
    for encoding in ("utf-16", "utf-8-sig", "utf-8", "cp1252"):
        if encoding == "utf-16" and raw[:2] not in (b"\xff\xfe", b"\xfe\xff"):
            continue
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def local_offset_hours(session_stem: str, first_capture_ts: float) -> float:
    """Work out the export's clock offset instead of assuming one.

    A session file is named in local time and its first record is epoch, so the
    two together give the offset that was in force during the run — including
    whichever side of a daylight-saving change it fell on, which a fixed
    constant would get wrong twice a year.
    """
    stamp = re.search(r"(\d{8})_(\d{6})", session_stem)
    if not stamp:
        raise ValueError(f"no timestamp in session name {session_stem!r}")
    local = datetime.strptime(stamp.group(1) + stamp.group(2), "%Y%m%d%H%M%S")
    utc = datetime.fromtimestamp(first_capture_ts, timezone.utc).replace(tzinfo=None)
    return round((local - utc).total_seconds() / 900.0) * 0.25


# ----- Questor / MAX300 ------------------------------------------------------


def load_questor(path: Path, tz_offset_h: float = 0.0) -> Tuple[List[str], List[Sample]]:
    """Read a Questor5 export: repeated Time / Time Relative / Ion Current triples.

    The species are named on one header row and the columns on the next, with
    each species contributing its own timestamp column. They are sampled
    together, so the first is used and the rest are checked rather than trusted.
    """
    lines = _text(path).splitlines()
    header_at = next(
        (i for i, l in enumerate(lines) if l.startswith("Time\tTime Relative")), None
    )
    if header_at is None or header_at == 0:
        raise ValueError(f"{Path(path).name} is not a Questor export")

    species = [s.strip() for s in lines[header_at - 1].split("\t")]
    fields = [f.strip() for f in lines[header_at].split("\t")]
    # Each species occupies three columns; its name sits above the first.
    current_of: Dict[str, int] = {}
    name = ""
    for index, field in enumerate(fields):
        if index < len(species) and species[index]:
            name = species[index]
        if field == "Ion Current [A]" and name:
            current_of.setdefault(name, index)

    columns = list(current_of)
    shift = timedelta(hours=tz_offset_h)
    samples: List[Sample] = []
    for line in lines[header_at + 1 :]:
        if not line.strip():
            continue
        cells = line.split("\t")
        try:
            when = datetime.strptime(cells[0].strip(), "%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, IndexError):
            continue
        row = {
            name: cells[i].strip()
            for name, i in current_of.items()
            if i < len(cells) and cells[i].strip()
        }
        if row:
            samples.append((when - shift, row))
    return columns, samples


# ----- Calisto / Setaram -----------------------------------------------------


def load_calisto(path: Path, tz_offset_h: float = 0.0) -> Tuple[List[str], List[Sample]]:
    """Read a Calisto export: a header block, then a fixed-width table.

    Absolute time comes from `Zone Start Time` in the header plus the table's
    elapsed `Time(s)`. Neither is sufficient alone, and an export whose header
    is missing is refused rather than placed at an assumed zero.
    """
    lines = _text(path).splitlines()
    start: Optional[datetime] = None
    for line in lines[:60]:
        if "Zone Start Time" in line:
            text = line.split(":", 1)[1].strip()
            for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%m/%y %H:%M:%S"):
                try:
                    start = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            break
    if start is None:
        raise ValueError(
            f"{Path(path).name} has no 'Zone Start Time' header, so its elapsed "
            "times cannot be placed on the capture clock"
        )

    header_at = next((i for i, l in enumerate(lines) if l.startswith("Index")), None)
    if header_at is None:
        raise ValueError(f"{Path(path).name} has no column header row")
    body = lines[header_at + 1 :]
    names = _calisto_columns(lines[header_at], body)

    elapsed_at = next(
        (i for i, n in enumerate(names) if n.lower().startswith("time(")), None
    )
    if elapsed_at is None:
        raise ValueError(f"{Path(path).name} has no Time(s) column")

    shift = timedelta(hours=tz_offset_h)
    columns = [
        n for i, n in enumerate(names)
        if i != elapsed_at and not _is_time_column(n) and n.lower() != "index"
    ]
    samples: List[Sample] = []
    for line in body:
        cells = line.split()
        if len(cells) < 2:
            continue
        try:
            when = start + timedelta(seconds=float(cells[elapsed_at]))
        except (ValueError, IndexError):
            continue
        row = {
            names[i]: cells[i]
            for i in range(min(len(cells), len(names)))
            if names[i] in columns
        }
        samples.append((when - shift, row))
    return columns, samples


def _calisto_columns(header: str, body: Sequence[str]) -> List[str]:
    """Name the columns of a fixed-width table whose names contain spaces.

    Splitting on whitespace does not work — `Furnace Temperature(°C)` contains
    one. Splitting on two-or-more spaces does not either: `Index Time(s)` is two
    names separated by exactly one, and merging them shifts every column by one,
    which does not fail. It just labels each reading with its neighbour's name.

    What holds throughout the file is that every name but the first ends in a
    bracketed unit, so a name boundary is a closing bracket followed by space.
    `Index` is the one bare name and is taken off the front explicitly.

    The result is checked against the number of fields in the widest data row,
    since an unnoticed miscount here is exactly the failure this is guarding
    against.
    """
    text = header.strip()
    names: List[str] = []
    if text.startswith("Index") and not text.startswith("Index("):
        names.append("Index")
        text = text[len("Index"):].lstrip()
    names.extend(n.strip() for n in re.split(r"(?<=[\)\]])\s+", text) if n.strip())

    fields = max((len(l.split()) for l in body[:200]), default=0)
    if fields and len(names) != fields:
        raise ValueError(
            f"read {len(names)} column names from the header but the table has "
            f"{fields} fields; the names would not line up with the values"
        )

    seen: Dict[str, int] = {}
    unique: List[str] = []
    for name in names:
        seen[name] = seen.get(name, 0) + 1
        unique.append(name if seen[name] == 1 else f"{name} #{seen[name]}")
    return unique


def constant_columns(
    samples: Sequence[Sample], columns: Sequence[str], tolerance: float = 1e-9
) -> List[str]:
    """Which columns never moved — nothing can identify these, in either file."""
    seen: Dict[str, List[float]] = {c: [] for c in columns}
    for _when, row in samples:
        for column in columns:
            text = row.get(column, "").strip()
            if not text:
                continue
            try:
                seen[column].append(float(text))
            except ValueError:
                continue
    flat = []
    for column, values in seen.items():
        if not values:
            flat.append(column)
            continue
        lo, hi = min(values), max(values)
        if hi - lo <= tolerance * max(abs(hi), abs(lo), 1.0):
            flat.append(column)
    return flat
