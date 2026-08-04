"""Turning raw log text into LogEntry objects."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import LogEntry, normalize_level

# Payload keys we promote onto LogEntry; everything else lands in `extra`.
_KNOWN_KEYS = {
    "timestamp",
    "time",
    "@timestamp",
    "level",
    "severity",
    "service",
    "logger",
    "host",
    "hostname",
    "message",
    "msg",
    "trace_id",
    "traceId",
    "exception",
    "error",
    "latency_ms",
}


def _first(payload: dict[str, Any], *keys: str) -> Any:
    """Return the first key present in the payload, or None."""
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating a trailing Z."""
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Parse one JSON log line. Returns None if the line isn't a JSON object."""
    stripped = line.strip()
    if not stripped:
        return None

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    latency = _first(payload, "latency_ms")
    return LogEntry(
        line_no=line_no,
        raw=stripped,
        level=normalize_level(_first(payload, "level", "severity")),
        timestamp=parse_timestamp(_first(payload, "timestamp", "time", "@timestamp")),
        service=_first(payload, "service", "logger"),
        host=_first(payload, "host", "hostname"),
        message=str(_first(payload, "message", "msg") or ""),
        trace_id=_first(payload, "trace_id", "traceId"),
        exception=_first(payload, "exception", "error"),
        latency_ms=float(latency) if isinstance(latency, (int, float)) else None,
        extra={k: v for k, v in payload.items() if k not in _KNOWN_KEYS},
    )


def load_entries(path: str | Path) -> tuple[list[LogEntry], int]:
    """Read a log file into entries.

    Returns the parsed entries plus a count of lines that could not be parsed,
    so callers can tell the difference between an empty log and an unreadable
    one.
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace")

    entries: list[LogEntry] = []
    skipped = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entry = parse_line(line, line_no)
        if entry is None:
            skipped += 1
        else:
            entries.append(entry)

    return entries, skipped
