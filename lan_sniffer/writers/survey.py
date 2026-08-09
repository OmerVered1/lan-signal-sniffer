"""Export everything a capture might contain, for analysis elsewhere.

A normal session records the signals a profile names. This exports the opposite:
every field the scan found plausible, from a device nobody has identified yet,
with wall-clock timestamps and the raw payload bytes alongside.

The point is to make an unrecognised instrument analysable by someone — or
something — that has information this app does not. Given this export and the
vendor software's own export of the same run, the two can be lined up on the
clock: a column that matches the vendor's temperature trace *is* the temperature,
and the moment its behaviour changes marks where the experiment started. Neither
fact is derivable from the bytes alone, which is exactly why the app does not
try to guess them.

Two files are written. The CSV holds the data. The JSON describes how to read it
and carries the profile schema, so whoever analyses the CSV can hand back a
config the app will accept without having to be told the format separately.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .._version import __version__
from ..protocol.fields import Candidate, scan_channel
from ..protocol.framer import Channel, FlowAnalysis, analyze_flow, group_chunks_by_flow
from ..protocol.fields import decode_field
from .csv_writer import SessionCSVWriter

# Candidates exported per channel. More than the identify wizard offers, since
# nothing here has to be read by a person at a glance and a wrong exclusion
# cannot be undone without repeating the experiment.
CANDIDATES_PER_CHANNEL = 12

SCHEMA_NOTE = "https://github.com/OmerVered1/lan-signal-sniffer"


@dataclass
class SurveyColumn:
    """One exported column: a candidate field, or a channel's raw bytes."""

    name: str
    channel_index: int
    channel_signature: str
    offset: Optional[int] = None
    encoding: Optional[str] = None
    score: float = 0.0
    is_constant: bool = False
    is_counter: bool = False
    minimum: float = 0.0
    maximum: float = 0.0
    raw_hex: bool = False

    def to_dict(self) -> dict:
        if self.raw_hex:
            return {
                "column": self.name,
                "channel": self.channel_signature,
                "content": "raw reply bytes, hex",
                "note": (
                    "Decode this yourself if none of the numeric columns match. "
                    "Every candidate column below is a reading of these bytes."
                ),
            }
        return {
            "column": self.name,
            "channel": self.channel_signature,
            "byte_offset": self.offset,
            "encoding": self.encoding,
            "plausibility_score": round(self.score, 4),
            "constant": self.is_constant,
            "looks_like_a_counter": self.is_counter,
            "observed_min": self.minimum,
            "observed_max": self.maximum,
        }


@dataclass
class Survey:
    """A full export: the columns, the rows, and how to interpret them."""

    columns: List[SurveyColumn] = field(default_factory=list)
    samples: List[Tuple[float, Dict[str, object]]] = field(default_factory=list)
    analysis: Optional[FlowAnalysis] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def column_names(self) -> List[str]:
        return [c.name for c in self.columns]


def _channel_label(index: int) -> str:
    return f"ch{index}"


def _modal_length(payloads: Sequence[bytes]) -> int:
    """The reply length the scan actually analysed."""
    if not payloads:
        return 0
    counts: Dict[int, int] = {}
    for p in payloads:
        counts[len(p)] = counts.get(len(p), 0) + 1
    return max(counts, key=lambda k: (counts[k], k))


def build_survey(chunks: Sequence, max_candidates: int = CANDIDATES_PER_CHANNEL) -> Survey:
    """Analyse a capture and lay out every plausible field as a column."""
    survey = Survey()
    flows = group_chunks_by_flow(chunks)
    if not flows:
        survey.warnings.append("no traffic was captured")
        return survey

    # The busiest connection is the instrument's; anything else on the same
    # host is incidental.
    largest = max(flows.values(), key=len)
    if len(flows) > 1:
        survey.warnings.append(
            f"{len(flows)} connections seen; exported the busiest "
            f"({len(largest)} chunks)"
        )
    analysis = analyze_flow(largest)
    survey.analysis = analysis
    survey.warnings.extend(analysis.warnings)

    if not analysis.channels:
        survey.warnings.append("no request/reply pattern emerged from the traffic")
        return survey

    # (ts, column -> value) accumulated across channels, sorted at the end so
    # the writer sees one chronological stream.
    rows: List[Tuple[float, Dict[str, object]]] = []

    for index, channel in enumerate(analysis.channels):
        label = _channel_label(index)
        scan = scan_channel(channel.payloads)
        survey.warnings.extend(f"{label}: {w}" for w in scan.warnings)

        # Alternatives are readings the scan outranked, not readings it
        # rejected. Excluding them would hide the very reading that turns out
        # to be right when the top pick is wrong.
        candidates: List[Candidate] = []
        for cand in scan.candidates:
            candidates.append(cand)
            candidates.extend(cand.alternatives)
        candidates.sort(key=lambda c: -c.score)
        candidates = candidates[:max_candidates]

        raw_column = SurveyColumn(
            name=f"{label}:hex",
            channel_index=index,
            channel_signature=channel.signature_hex,
            raw_hex=True,
        )
        survey.columns.append(raw_column)

        decoded: List[Tuple[SurveyColumn, list]] = []
        for cand in candidates:
            column = SurveyColumn(
                name=f"{label}@{cand.offset}:{cand.encoding}",
                channel_index=index,
                channel_signature=channel.signature_hex,
                offset=cand.offset,
                encoding=cand.encoding,
                score=cand.score,
                is_constant=cand.is_constant,
                is_counter=cand.is_counter,
                minimum=cand.minimum,
                maximum=cand.maximum,
            )
            survey.columns.append(column)
            decoded.append(
                (column, decode_field(channel.payloads, cand.offset, cand.encoding))
            )

        for i, (ts, payload) in enumerate(zip(channel.timestamps, channel.payloads)):
            values: Dict[str, object] = {raw_column.name: payload.hex()}
            for column, series in decoded:
                value = series[i]
                if value == value:  # not NaN
                    values[column.name] = float(value)
            rows.append((ts, values))

    rows.sort(key=lambda r: r[0])
    survey.samples = rows
    return survey


def _metadata(survey: Survey, device_ip: str, device_port: Optional[int]) -> dict:
    analysis = survey.analysis
    channels = []
    if analysis:
        for index, channel in enumerate(analysis.channels):
            channels.append(
                {
                    "id": _channel_label(index),
                    "request_hex": channel.signature_hex,
                    "request_mask": [bool(m) for m in channel.mask],
                    "replies": channel.count,
                    "median_period_s": channel.median_period(),
                    # The modal length, not the first reply's. A device can
                    # answer once with a longer combined frame at connect time,
                    # and reporting that would send an analyst looking for
                    # fields at offsets the steady-state reply does not have.
                    "reply_length_bytes": _modal_length(channel.payloads),
                }
            )

    return {
        "produced_by": f"LAN Signal Sniffer {__version__}",
        "project": SCHEMA_NOTE,
        "device": {"ip": device_ip, "port": device_port},
        "capture": {
            "interaction": analysis.interaction if analysis else "unknown",
            "request_framing": (
                analysis.request_spec.to_dict()
                if analysis and analysis.request_spec
                else None
            ),
            "response_framing": (
                analysis.response_spec.to_dict()
                if analysis and analysis.response_spec
                else None
            ),
        },
        "channels": channels,
        "columns": [c.to_dict() for c in survey.columns],
        "warnings": survey.warnings,
        "how_to_read_this": [
            "Every row is one poll cycle. timestamp_utc is the capture clock, "
            "so rows can be aligned against the instrument software's own "
            "export of the same run.",
            "A channel is one request the software repeats. Each 'chN@offset:"
            "encoding' column is one way of reading that channel's reply; "
            "columns from the same channel that overlap in bytes are competing "
            "readings of the same field, not separate measurements.",
            "'chN:hex' is the untouched reply. If no numeric column matches a "
            "known trace, the value is in there and was read the wrong way.",
            "plausibility_score is this app's guess, nothing more. A low score "
            "on a column that matches a known trace means the guess was wrong.",
            "To find where an experiment starts, compare against the vendor "
            "export: the app cannot tell a run from an idle poll without it.",
        ],
        "profile_schema": _profile_schema(),
    }


def _profile_schema() -> dict:
    """The config format the app imports, described inline.

    Carried in the export so that whoever analyses the CSV can return something
    importable without being sent the format separately.
    """
    return {
        "description": (
            "Save as JSON and load it with 'Import profile…'. One entry in "
            "'signals' per quantity worth recording; its 'name' becomes the CSV "
            "column heading."
        ),
        "example": {
            "version": 1,
            "name": "My Instrument",
            "mac": "",
            "ip_hint": "",
            "device_port": 1210,
            "interaction": "request_response",
            "request_framing": {
                "mode": "fixed  (one of: fixed, length_prefixed, text, single_segment)",
                "frame_len": 6,
            },
            "signals": [
                {
                    "name": "heat_flow",
                    "unit": "mW",
                    "signature": "hex of the request that asks for it, "
                    "copied from channels[].request_hex without the dots",
                    "mask": "list of true/false, one per request byte; false "
                    "where channels[].request_mask is false",
                    "offset": 6,
                    "encoding": "f32be",
                    "scale": 1.0,
                    "bias": 0.0,
                }
            ],
            "session": {"mode": "manual"},
        },
        "encodings": [
            "f32be", "f32le", "f64be", "f64le",
            "i16be", "i16le", "u16be", "u16le",
            "i32be", "i32le", "u32be", "u32le",
            "ascii#N  (the Nth number in a text reply)",
        ],
        "notes": [
            "value_recorded = raw * scale + bias. Use scale for instruments "
            "reporting counts — a register holding 1503 for 150.3 needs 0.1.",
            "'signature' and 'mask' must come from the same channel the column "
            "belongs to, or the signal will never match a live request.",
            "Masked positions (false) are request bytes that vary like a "
            "counter and are ignored when matching.",
        ],
    }


def write_survey(
    survey: Survey,
    csv_path: Path,
    device_ip: str = "",
    device_port: Optional[int] = None,
) -> Tuple[Path, Path]:
    """Write the survey CSV and its companion metadata JSON."""
    csv_path = Path(csv_path)
    json_path = csv_path.with_suffix(".json")

    with SessionCSVWriter(csv_path, survey.column_names) as writer:
        for ts, values in survey.samples:
            writer.add(ts, values)

    json_path.write_text(
        json.dumps(_metadata(survey, device_ip, device_port), indent=2) + "\n",
        encoding="utf-8",
    )
    return csv_path, json_path
