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


# ----- talking to it --------------------------------------------------------


def local_to_epoch(when: datetime) -> float:
    """Put Questor's stamp on the capture clock.

    The stamps carry no time zone, so they are the analyser PC's local clock.
    The sniffer normally runs on that same PC, so the machine's own offset is
    the right conversion and needs no configuring - and unlike a typed offset,
    it cannot be wrong about daylight saving.
    """
    return when.astimezone().timestamp()


class Transport:
    """How the request actually gets sent.

    The endpoint requires Windows authentication - anonymous is refused - so
    this cannot be a plain socket write. Two ways of doing it exist on every
    machine that runs Questor, and which is available is decided at run time
    rather than assumed:

      * `curl.exe`, shipped with Windows since 1803, with NTLM through SSPI.
        Needs nothing installed and no Python package.
      * `WinHttp.WinHttpRequest.5.1` through COM, which is essentially the
        object Questor's own page uses. Needs pywin32.

    Negotiate is not offered: this server answers 401 to it and 200 to NTLM.
    """

    name = "none"

    def post(self, url: str, body: bytes, timeout_s: float) -> bytes:
        raise NotImplementedError


class CurlTransport(Transport):
    name = "curl"

    def __init__(self) -> None:
        import shutil

        self.exe = shutil.which("curl.exe") or shutil.which("curl")
        if not self.exe:
            raise RuntimeError("curl was not found on this machine")

    @staticmethod
    def _hidden() -> dict:
        """Keep Windows from flashing a console window for every request.

        A GUI application spawning a console program gets a new console for it,
        and at one request every few seconds that is a black window appearing
        and vanishing all day. It is only cosmetic, and it makes the app look
        broken enough that nobody would leave it running for a thirteen-hour
        experiment - which is the entire point of it.
        """
        import subprocess
        import sys

        if not sys.platform.startswith("win"):
            return {}
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE, for consoles that appear anyway
        return {
            "startupinfo": startupinfo,
            "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        }

    def post(self, url: str, body: bytes, timeout_s: float) -> bytes:
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as handle:
            handle.write(body)
            path = handle.name
        try:
            done = subprocess.run(
                [
                    self.exe, "-s", "--ntlm", "-u", ":",
                    "-X", "POST",
                    "-H", "Content-Type: text/xml",
                    "-H", "Content-Source: Transport",
                    "--data-binary", "@" + path,
                    "--max-time", str(int(max(1, timeout_s))),
                    url,
                ],
                capture_output=True,
                timeout=timeout_s + 5,
                **self._hidden(),
            )
        finally:
            try:
                __import__("os").unlink(path)
            except OSError:
                pass
        if done.returncode != 0:
            raise RuntimeError(
                f"curl failed ({done.returncode}): "
                + (done.stderr.decode("utf-8", "replace").strip() or "no detail")
            )
        return done.stdout


class WinHttpTransport(Transport):
    name = "winhttp"

    def __init__(self) -> None:
        import win32com.client  # noqa: F401  (import is the availability test)

        self._client = win32com.client

    def post(self, url: str, body: bytes, timeout_s: float) -> bytes:
        http = self._client.Dispatch("WinHttp.WinHttpRequest.5.1")
        ms = int(timeout_s * 1000)
        http.SetTimeouts(ms, ms, ms, ms)
        http.Open("POST", url, False)
        http.SetRequestHeader("Content-Type", "text/xml")
        http.SetRequestHeader("Content-Source", "Transport")
        http.SetAutoLogonPolicy(0)
        http.Send(body.decode("utf-8"))
        if int(http.Status) != 200:
            raise RuntimeError(f"HTTP {http.Status} {http.StatusText}")
        return http.ResponseText.encode("utf-8")


def open_transport() -> Transport:
    """Whichever way of sending a request this machine actually has."""
    problems = []
    # WinHTTP first where it exists: it is in-process, so there is no console
    # to suppress and no program to find, and it keeps its connection open.
    for factory in (WinHttpTransport, CurlTransport):
        try:
            return factory()
        except Exception as e:  # ImportError, RuntimeError, COM errors
            problems.append(f"{factory.name}: {e}")
    raise RuntimeError(
        "no way to send an authenticated request was available - "
        + "; ".join(problems)
    )


@dataclass
class QuestorClient:
    """Polls Questor for results, returning only ones not seen before.

    Asks for several at a time. Results appear about every eight seconds and a
    poll that is late, or an app that was busy, would otherwise lose the ones
    in between - the server keeps a short history and handing back a few costs
    nothing.

    Identity is the valve and the timestamp together, because the same instant
    on two valves is two different measurements.
    """

    host: str = "localhost"
    port: int = DEFAULT_PORT
    path: str = DEFAULT_PATH
    count: int = 5
    timeout_s: float = DEFAULT_TIMEOUT_S
    transport: Optional[Transport] = None
    last_error: str = ""
    # When this client started looking. Each poll asks for several results so
    # that a late one can catch up, which means the first reply carries a
    # history reaching back before the app was even watching. Those are real
    # measurements, but they are not part of this recording, and writing them
    # into it would put readings in a session that predate it.
    since: Optional[datetime] = None
    # Every tag name and unit seen, including from the first reply that is not
    # recorded. A session fixes its columns when it opens, so the names have to
    # be known before then - and the reply that establishes the history
    # boundary is usually the only one that has arrived by that point.
    tags: List[str] = field(default_factory=list)
    units: Dict[str, str] = field(default_factory=dict)
    _seen: set = field(default_factory=set)

    @property
    def url(self) -> str:
        port = "" if self.port in (80, None) else f":{self.port}"
        return f"http://{self.host}{port}{self.path}"

    def open(self) -> None:
        if self.transport is None:
            self.transport = open_transport()
        self.last_error = ""

    def close(self) -> None:
        self.transport = None

    def reset(self) -> None:
        """Forget what has been seen, so a new session starts clean."""
        self._seen.clear()
        self.last_error = ""
        self.since = None
        # Tag names are deliberately kept: they describe the instrument, not
        # the recording, and a session that has already written its header
        # cannot gain columns afterwards.

    def poll(self) -> List[ResultSet]:
        """Result sets that have appeared since the last call, oldest first."""
        if self.transport is None:
            self.open()
        try:
            payload = self.transport.post(self.url, build_request(self.count), self.timeout_s)
            results = parse_results(payload)
        except Exception as e:
            self.last_error = str(e)
            return []
        self.last_error = ""
        self._learn(results)

        if self.since is None and results:
            # The whole of the first reply is history. Every poll asks for
            # several so a late one can catch up, so the first one hands back
            # whatever the instrument already had - readings that happened
            # before anyone was watching. Keeping the oldest of them as the
            # boundary kept the rest, which is how measurements from twenty
            # seconds before a session ended up inside it with a negative
            # elapsed time. The boundary is the newest of that reply, and only
            # what comes after it belongs to this recording.
            self.since = max(r.when for r in results)
            for result in results:
                self._seen.add(result.key)
            return []

        fresh = [
            r for r in results
            if r.key not in self._seen
            and (self.since is None or r.when > self.since)
        ]
        for result in fresh:
            self._seen.add(result.key)
        if len(self._seen) > 4096:
            # Unbounded growth over a long run; keep the recent tail, which is
            # all that a few-deep history can ever repeat.
            self._seen = set(sorted(self._seen, key=lambda k: k[1])[-1024:])
        return fresh

    def latest(self) -> List[ResultSet]:
        """One request, parsed, with none of the recording rules applied.

        `poll` exists to feed a session, so it drops the first reply as history
        and never repeats a result. Neither is right for someone checking
        whether the thing answers at all - a single look would come back empty
        every time and read as a broken connection.

        Raises rather than reporting through `last_error`, because a caller
        asking "does this work" wants the reason, not a quiet empty list.
        """
        if self.transport is None:
            self.open()
        payload = self.transport.post(self.url, build_request(self.count), self.timeout_s)
        results = parse_results(payload)
        self._learn(results)
        return results

    def _learn(self, results: Sequence[ResultSet]) -> None:
        """Remember what this instrument calls things, whatever is recorded."""
        for result in results:
            for name in result.values:
                if name not in self.tags:
                    self.tags.append(name)
            self.units.update(result.units)

    def status(self) -> str:
        if self.last_error:
            return f"Questor: {self.last_error}"
        if self.transport is None:
            return "Questor: not connected"
        return f"Questor: reading ({self.transport.name})"
