"""The parsed representation of a single log line."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Levels we recognise, ordered from least to most severe.
LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")

# Common spellings that mean the same thing as one of the above.
LEVEL_ALIASES = {
    "WARNING": "WARN",
    "ERR": "ERROR",
    "SEVERE": "ERROR",
    "CRITICAL": "FATAL",
    "CRIT": "FATAL",
    "TRACE": "DEBUG",
}

# Levels that count as a failure when computing error rates.
FAILURE_LEVELS = ("ERROR", "FATAL")


def normalize_level(level: Any) -> str:
    """Map a raw level string onto one of LEVELS, or UNKNOWN."""
    if not isinstance(level, str):
        return "UNKNOWN"
    value = level.strip().upper()
    value = LEVEL_ALIASES.get(value, value)
    return value if value in LEVELS else "UNKNOWN"


@dataclass
class LogEntry:
    """One log line, with the fields we analyse pulled out of the payload.

    Anything we don't model explicitly stays in `extra`, so tools can surface
    context like pod names or connection counts without us knowing about them
    ahead of time.
    """

    line_no: int
    raw: str
    level: str = "UNKNOWN"
    timestamp: datetime | None = None
    service: str | None = None
    host: str | None = None
    message: str = ""
    trace_id: str | None = None
    exception: str | None = None
    latency_ms: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_failure(self) -> bool:
        return self.level in FAILURE_LEVELS

    def one_line(self) -> str:
        """Compact single-line rendering used in tool output."""
        stamp = self.timestamp.strftime("%H:%M:%S") if self.timestamp else "--:--:--"
        where = self.service or "unknown"
        text = f"{stamp} {self.level:<5} {where:<22} {self.message}"
        if self.exception:
            text += f"  [{self.exception}]"
        return text
