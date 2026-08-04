"""Turning raw log text into LogEntry objects.

Real logs are not all JSON, are sometimes gzipped, are sometimes enormous, and
frequently wrap a stack trace across many physical lines. This module handles
all four while holding memory bounded.
"""

import gzip
import json
import re
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import IO, Any

from .models import FAILURE_LEVELS, LogEntry, normalize_level
from .redact import redact
from .safety import detect_injection

# Upper bound on entries held in memory from a single file. Large enough that
# ordinary logs are never affected, small enough that a runaway file cannot
# exhaust memory: retained entries cost roughly 500 bytes each, so this caps
# peak usage at around 50 MB regardless of how big the file on disk is.
DEFAULT_MAX_ENTRIES = 100_000

# Payload keys we promote onto LogEntry; everything else lands in `extra`.
_KNOWN_KEYS = {
    "timestamp",
    "time",
    "@timestamp",
    "ts",
    "level",
    "severity",
    "lvl",
    "service",
    "logger",
    "host",
    "hostname",
    "message",
    "msg",
    "trace_id",
    "traceId",
    "traceID",
    "exception",
    "error",
    "stack_trace",
    "latency_ms",
    "duration_ms",
    "elapsed_ms",
}


# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------

_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",  # apache/nginx access
)

# Syslog omits the year. Parsing it yearless is deprecated from Python 3.15,
# so the current year is prepended before parsing rather than patched in after.
_YEARLESS_FORMATS = (("%b %d %H:%M:%S", "%Y %b %d %H:%M:%S"),)


def _as_aware(value: datetime) -> datetime:
    """Attach UTC to a naive timestamp.

    A single file can mix formats that carry an offset (JSON with a trailing Z)
    and formats that don't (logback, syslog). Without a common convention the
    two are not comparable at all, so naive timestamps are read as UTC.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the timestamp formats that show up in practice.

    Syslog omits the year; we assume the current one, which is what every
    other syslog reader does. All results are timezone-aware — see _as_aware.
    """
    if isinstance(value, datetime):
        return _as_aware(value)
    if isinstance(value, (int, float)):
        # Heuristic: values past ~2001 in ms are too large to be seconds.
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OSError, ValueError, OverflowError):
            return None
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        return _as_aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        pass

    for fmt in _TIMESTAMP_FORMATS:
        try:
            return _as_aware(datetime.strptime(text, fmt))
        except ValueError:
            continue

    year = datetime.now().year
    for _, dated_fmt in _YEARLESS_FORMATS:
        try:
            return _as_aware(datetime.strptime(f"{year} {text}", dated_fmt))
        except ValueError:
            continue

    return None


# --------------------------------------------------------------------------
# text formats
# --------------------------------------------------------------------------

_LEVEL_WORDS = (
    "TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|SEVERE|CRIT|CRITICAL|"
    "FATAL|ALERT|EMERG|PANIC"
)

# Each pattern is tried in order. Named groups map onto LogEntry fields.
_TEXT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        # logback / log4j / python logging:
        #   2026-07-30 20:15:31,123 ERROR [order-service] com.foo.Bar - message
        "logback",
        re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
            r"(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            rf"(?P<level>{_LEVEL_WORDS})\b:?\s*"
            r"(?:\[(?P<service>[^\]]+)\]\s*)?"
            r"(?:(?P<logger>[\w.$]+)\s+-\s+)?"
            r"(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # nginx error log:
        #   2026/07/30 20:15:31 [error] 1234#0: *1 upstream timed out
        "nginx",
        re.compile(
            r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
            rf"\[(?P<level>{_LEVEL_WORDS})\]\s+"
            r"(?P<pid>\d+)#\d+:\s*(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # syslog:
        #   Jul 30 20:15:31 web-01 nginx[1234]: message
        "syslog",
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*"
            r"(?P<message>.*)$"
        ),
    ),
    (
        # fully bracketed:
        #   [2026-07-30T20:15:31Z] [ERROR] [order-service] message
        "bracketed",
        re.compile(
            r"^\[(?P<timestamp>[^\]]+)\]\s*"
            rf"\[(?P<level>{_LEVEL_WORDS})\]\s*"
            r"(?:\[(?P<service>[^\]]+)\]\s*)?"
            r"(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # last resort: a level word somewhere in the line, optional leading
        # timestamp. Catches ad-hoc formats rather than discarding them.
        "loose",
        re.compile(
            r"^(?:(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}"
            r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+)?"
            rf"(?P<pre>.*?)\b(?P<level>{_LEVEL_WORDS})\b[:\s-]+"
            r"(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
)

# Lines that continue the previous entry rather than starting a new one.
_CONTINUATION = re.compile(
    r"^(?:\s+|at\s|Caused by:|\.\.\.\s*\d+\s+more|Traceback|\s*File\s\")",
)

# Java/Python exception header inside a stack trace, used to fill in the
# exception field when the log line itself didn't carry one.
_EXCEPTION_HEADER = re.compile(
    r"^(?:Caused by:\s*)?(?P<exc>(?:[\w$]+\.)*[\w$]*(?:Exception|Error)\b[^\n]{0,200})"
)


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def parse_json_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Parse one JSON object line."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None

    latency = _first(payload, "latency_ms", "duration_ms", "elapsed_ms")
    return LogEntry(
        line_no=line_no,
        raw=line,
        level=normalize_level(_first(payload, "level", "severity", "lvl")),
        timestamp=parse_timestamp(_first(payload, "timestamp", "time", "@timestamp", "ts")),
        service=_first(payload, "service", "logger"),
        host=_first(payload, "host", "hostname"),
        message=str(_first(payload, "message", "msg") or ""),
        trace_id=_first(payload, "trace_id", "traceId", "traceID"),
        exception=_first(payload, "exception", "error", "stack_trace"),
        latency_ms=float(latency) if isinstance(latency, (int, float)) else None,
        extra={k: v for k, v in payload.items() if k not in _KNOWN_KEYS},
    )


def parse_text_line(line: str, line_no: int = 0) -> tuple[LogEntry | None, str]:
    """Parse one non-JSON line, returning the entry and the format that matched."""
    for name, pattern in _TEXT_PATTERNS:
        match = pattern.match(line)
        if not match:
            continue
        groups = match.groupdict()

        level = normalize_level(groups.get("level"))
        # The loose pattern will otherwise match a level word inside ordinary
        # prose — "The error was caused by ..." would become an ERROR entry and
        # inflate the error count. Require real log structure: either a parsed
        # timestamp, or the level word at the very start of the line.
        if name == "loose":
            has_timestamp = parse_timestamp(groups.get("timestamp")) is not None
            starts_with_level = not (groups.get("pre") or "").strip()
            if level == "UNKNOWN" or not (has_timestamp or starts_with_level):
                continue

        # nginx error lines carry no service field, but we know what wrote them.
        service = groups.get("service") or groups.get("logger")
        if service is None and name == "nginx":
            service = "nginx"

        return (
            LogEntry(
                line_no=line_no,
                raw=line,
                level=level,
                timestamp=parse_timestamp(groups.get("timestamp")),
                service=service,
                host=groups.get("host"),
                message=(groups.get("message") or "").strip(),
            ),
            name,
        )
    return None, ""


def sanitize(
    entry: LogEntry, redact_secrets: bool = True, counts: Counter | None = None
) -> LogEntry:
    """Flag injection attempts and strip credentials, in that order.

    Injection detection runs on the original text: redaction rewrites parts of
    a line and could otherwise hide the phrasing that gives an attempt away.
    """
    findings = detect_injection(entry.message) or detect_injection(entry.raw)
    if findings:
        entry.injection = tuple(sorted({f.kind for f in findings}))

    if redact_secrets:
        # `raw` holds the same content as `message` in serialized form, so it
        # is cleaned but not counted — otherwise every secret is reported twice.
        entry.raw = redact(entry.raw).text
        for field_name in ("message", "exception"):
            value = getattr(entry, field_name)
            if value:
                result = redact(value)
                setattr(entry, field_name, result.text)
                if counts is not None:
                    counts.update(result.counts)
        if entry.detail:
            cleaned = []
            for line in entry.detail:
                result = redact(line)
                cleaned.append(result.text)
                if counts is not None:
                    counts.update(result.counts)
            entry.detail = cleaned

    return entry


def parse_line(line: str, line_no: int = 0, redact_secrets: bool = True) -> LogEntry | None:
    """Parse a single line in any supported format."""
    stripped = line.strip()
    if not stripped:
        return None
    entry = parse_json_line(stripped, line_no)
    if entry is None:
        entry, _ = parse_text_line(stripped, line_no)
    if entry is None:
        return None
    return sanitize(entry, redact_secrets)


# --------------------------------------------------------------------------
# file access
# --------------------------------------------------------------------------


def open_log(path: Path) -> IO[str]:
    """Open a log file, transparently decompressing .gz."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


@dataclass
class LoadResult:
    """What was read, and honestly.

    `entries` holds detail for at most `max_entries` lines. The `total_*`
    fields are accumulated over the entire file, so counts and rates stay
    correct even when detail had to be dropped.
    """

    entries: list[LogEntry]
    total_lines: int = 0
    total_entries: int = 0
    skipped: int = 0
    truncated: bool = False
    formats: Counter = field(default_factory=Counter)
    total_by_level: Counter = field(default_factory=Counter)
    redactions: Counter = field(default_factory=Counter)
    suspicious: int = 0

    @property
    def total_failures(self) -> int:
        return sum(self.total_by_level.get(level, 0) for level in FAILURE_LEVELS)

    @property
    def error_rate(self) -> float:
        """Failure rate over the whole file, not just the retained window."""
        return (self.total_failures / self.total_entries * 100) if self.total_entries else 0.0

    @property
    def format_summary(self) -> str:
        if not self.formats:
            return "unknown"
        return ", ".join(f"{name} ({n})" for name, n in self.formats.most_common())


def _is_continuation(line: str) -> bool:
    """Does this unparseable line belong to the entry above it?

    The header of a Java stack trace ("java.net.SocketTimeoutException: ...")
    sits flush against the left margin, so indentation alone is not enough to
    recognise it — and it is the line that names the real exception.
    """
    return bool(_CONTINUATION.match(line) or _EXCEPTION_HEADER.match(line.strip()))


def _absorb(entry: LogEntry, line: str) -> None:
    """Fold a continuation line into the entry it belongs to."""
    entry.detail.append(line)
    if entry.exception is None:
        header = _EXCEPTION_HEADER.match(line)
        if header:
            entry.exception = header.group("exc").strip()


def iter_entries(path: str | Path, redact_secrets: bool = True) -> Iterator[LogEntry]:
    """Stream entries one at a time, in file order, with bounded memory.

    An entry is only yielded once the following line proves it complete, so
    continuation lines land on the entry they belong to.
    """
    pending: LogEntry | None = None

    with open_log(Path(path)) as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n\r")
            if not line.strip():
                continue

            stripped = line.strip()
            entry = parse_json_line(stripped, line_no)
            if entry is None:
                entry, _ = parse_text_line(stripped, line_no)

            if entry is None:
                if pending is not None and _is_continuation(line):
                    _absorb(pending, stripped)
                continue

            if pending is not None:
                yield sanitize(pending, redact_secrets)
            pending = entry

    if pending is not None:
        yield sanitize(pending, redact_secrets)


def load_entries(
    path: str | Path,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    redact_secrets: bool = True,
) -> LoadResult:
    """Read a log file, keeping counts for all of it and detail for the tail.

    The earlier version kept the *first* max_entries lines and dropped the
    rest. Incidents are at the end of a log, so that discarded exactly the
    part worth reading and reported rates from the least relevant window.

    Now the whole file is streamed: level counts, formats and redactions
    accumulate over every line, while retained detail is the most recent
    max_entries entries.
    """
    result = LoadResult(entries=[])
    retained: deque[LogEntry] = deque(maxlen=max(max_entries, 1))
    parsed_lines = 0
    pending: LogEntry | None = None

    def complete(entry: LogEntry) -> None:
        sanitize(entry, redact_secrets, result.redactions)
        result.total_entries += 1
        result.total_by_level[entry.level] += 1
        if entry.suspicious:
            result.suspicious += 1
        retained.append(entry)

    with open_log(Path(path)) as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n\r")
            if not line.strip():
                continue
            result.total_lines += 1

            stripped = line.strip()
            entry = parse_json_line(stripped, line_no)
            fmt = "json" if entry is not None else ""
            if entry is None:
                entry, fmt = parse_text_line(stripped, line_no)

            if entry is None:
                if pending is not None and _is_continuation(line):
                    _absorb(pending, stripped)
                    parsed_lines += 1
                continue

            parsed_lines += 1
            result.formats[fmt] += 1

            if pending is not None:
                complete(pending)
            pending = entry

    if pending is not None:
        complete(pending)

    result.entries = list(retained)
    result.skipped = result.total_lines - parsed_lines
    result.truncated = result.total_entries > len(result.entries)
    return result


_RELATIVE = re.compile(r"^(\d+)\s*([smhdw])$", re.I)
_RELATIVE_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_time_spec(value: str | None, now: datetime | None = None) -> datetime | None:
    """Parse a time window bound.

    Accepts an absolute timestamp in any format the log parser understands, or
    a relative offset into the past such as '30m', '2h', '7d'. Relative values
    are what a responder actually types, and are resolved against `now`.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    match = _RELATIVE.match(text)
    if match:
        amount, unit = int(match.group(1)), match.group(2).lower()
        base = now or datetime.now(UTC)
        return base - timedelta(seconds=amount * _RELATIVE_UNITS[unit])

    parsed = parse_timestamp(text)
    if parsed is None:
        raise ValueError(
            f"could not read '{value}' as a time. Use an absolute timestamp "
            "such as 2026-07-30T20:15:00Z, or a relative offset such as 30m, 2h or 7d."
        )
    return parsed
