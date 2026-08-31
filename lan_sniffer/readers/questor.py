# READ-ONLY MODULE
"""Ask Questor5 for the values it is displaying, over its own web interface.

A process mass spectrometer computes its concentrations in software: nothing on
the instrument's own link carries them, which four hours of captured traffic and
two independent searches confirmed. But Questor5's user interface is a web
application served by IIS on the analyser PC, and the results pane keeps itself
up to date by polling a SOAP endpoint once a second. The numbers cross HTTP to
reach the screen, and asking for them the same way the browser does is the
supported route rather than a workaround.

    POST /questor5/Soap/ResultServer.asp
    Content-Type: text/xml
    Content-Source: Transport

The dispatcher in `Include/SoapCommon.inc` takes the body's element name, strips
the `Lazarus:` prefix and lower-cases the rest to pick a function, so
`Lazarus:GetResults` calls `getresults()`. That function reads `Count` and
`From` and returns result sets. It only reads.

What comes back carries an absolute timestamp per result set, which is what
makes these values line up with a sniffed instrument rather than merely sitting
beside them:

    <ResultSet>
      <ValveId>1</ValveId>
      <TimeStamp>2026-08-31T13:14:35.527</TimeStamp>
      <Result sts="128">
        <Tag id="V1_I_18" value="7.271817207336" raw="7.271817207336"/>
        <Tag id="V1_C_H2" value="0.009795228951" unit="%"/>
      </Result>
    </ResultSet>
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple
from xml.etree import ElementTree

DEFAULT_PATH = "/questor5/Soap/ResultServer.asp"
DEFAULT_PORT = 80
# One second is what the vendor's own page uses; there is no point asking faster
# than the instrument produces results.
DEFAULT_INTERVAL_S = 1.0
DEFAULT_TIMEOUT_S = 5.0

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
LAZARUS_NS = "http://us.abb.com/extrel/Lazarus/"

REQUEST = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="{soap}" xmlns:Lazarus="{lazarus}">'
    "<SOAP-ENV:Header><Lazarus:Params><From>{who}</From></Lazarus:Params>"
    "</SOAP-ENV:Header>"
    "<SOAP-ENV:Body><Lazarus:GetResults><Count>{count}</Count><From></From>"
    "</Lazarus:GetResults></SOAP-ENV:Body></SOAP-ENV:Envelope>"
)


def build_request(count: int = 1, who: str = "lan-signal-sniffer") -> bytes:
    """The envelope to POST. `count` is how many recent result sets to return."""
    return REQUEST.format(
        soap=SOAP_NS, lazarus=LAZARUS_NS, count=int(count), who=who
    ).encode("utf-8")


@dataclass
class ResultSet:
    """One analysis result: a moment, a valve, and the tags read at it."""

    when: datetime
    valve: str
    values: Dict[str, float] = field(default_factory=dict)
    units: Dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, datetime]:
        """What makes this result set distinct from another."""
        return (self.valve, self.when)


def _fault(root: ElementTree.Element) -> Optional[str]:
    """The message from a SOAP fault, if the response is one."""
    for tag in ("faultstring", "Message"):
        node = next((n for n in root.iter() if n.tag.endswith(tag)), None)
        if node is not None and (node.text or "").strip():
            return node.text.strip()
    return None


def parse_timestamp(text: str) -> Optional[datetime]:
    """Read Questor's stamp. It has no zone, so it is the PC's local clock."""
    text = (text or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_results(payload: bytes) -> List[ResultSet]:
    """Pull the result sets out of a response.

    A fault is raised rather than returned empty: an empty list means the
    instrument had nothing new, and confusing that with a refused request would
    turn a broken connection into an apparently idle one.
    """
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as e:
        raise ValueError(f"response was not XML: {e}") from e

    if any(n.tag.endswith("Fault") for n in root.iter()):
        raise ValueError(_fault(root) or "the server returned a SOAP fault")

    out: List[ResultSet] = []
    for node in (n for n in root.iter() if n.tag.endswith("ResultSet")):
        stamp = next((c for c in node.iter() if c.tag.endswith("TimeStamp")), None)
        when = parse_timestamp(stamp.text if stamp is not None else "")
        if when is None:
            # Without a time there is nothing to line these values up against,
            # and a guessed one would be worse than dropping the row.
            continue
        valve = next((c for c in node.iter() if c.tag.endswith("ValveId")), None)
        entry = ResultSet(when=when, valve=(valve.text or "").strip() if valve is not None else "")
        for tag in (c for c in node.iter() if c.tag.endswith("Tag")):
            name = (tag.get("id") or "").strip()
            if not name:
                continue
            try:
                entry.values[name] = float(tag.get("value"))
            except (TypeError, ValueError):
                continue
            unit = (tag.get("unit") or "").strip()
            if unit:
                entry.units[name] = unit
        if entry.values:
            out.append(entry)
    out.sort(key=lambda r: r.when)
    return out
