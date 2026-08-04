"""The parsed representation of a single log line."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Levels we recognise, ordered from least to most severe.
LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")

# Common spellings that mean the same thing as one of the above.
LEVEL_ALIASES = {
    "WARNING": "WARN",
    "WARNING:": "WARN",
    "ERR": "ERROR",
    "SEVERE": "ERROR",
    "CRITICAL": "FATAL",
    "CRIT": "FATAL",
    "TRACE": "DEBUG",
    "FINE": "DEBUG",
    "VERBOSE": "DEBUG",
    # syslog severities
    "EMERG": "FATAL",
    "PANIC": "FATAL",
    "ALERT": "FATAL",
    "NOTICE": "INFO",
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


# slots=True drops the per-instance __dict__. At a few hundred thousand
# retained entries that overhead is the difference between tens and hundreds
# of megabytes.
@dataclass(slots=True)
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
    # Continuation lines belonging to this entry, e.g. a Java stack trace.
    detail: list[str] = field(default_factory=list)

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
        if self.detail:
            text += f"  (+{len(self.detail)} line(s) of stack trace)"
        return text
