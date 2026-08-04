"""LangChain tools. These wrap the analysis functions and render their results
as compact text, because that is what the model actually consumes."""

from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from . import analysis
from .parser import LoadResult, load_entries

# Hard ceiling on how many entries any tool will echo back, so a large log can
# never blow out the model's context window.
MAX_RETURNED_ENTRIES = 100

# One investigation makes several tool calls against the same file; parsing it
# once per call is wasted work. Keyed on identity plus mtime and size so an
# actively-written log is re-read when it changes.
_CACHE: dict[tuple[str, int, int], LoadResult] = {}
_CACHE_LIMIT = 4


class _LoadError(Exception):
    """Raised when a log file can't be read, carrying a model-facing message."""


def _load(path: str) -> LoadResult:
    """Load a log file, converting filesystem errors into _LoadError."""
    target = Path(path).expanduser()
    try:
        stat = target.stat()
        key = (str(target.resolve()), stat.st_mtime_ns, stat.st_size)
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        result = load_entries(target)
    except FileNotFoundError:
        raise _LoadError(f"No log file at '{path}'. Ask the user for the correct path.")
    except IsADirectoryError:
        raise _LoadError(f"'{path}' is a directory, not a log file.")
    except PermissionError:
        raise _LoadError(f"Permission denied reading '{path}'.")
    except UnicodeDecodeError:
        raise _LoadError(f"'{path}' is not text — it may be a binary file.")
    except OSError as exc:
        raise _LoadError(f"Could not read '{path}': {exc}")

    if not result.entries:
        raise _LoadError(
            f"Parsed no log entries from '{path}' ({result.total_lines} line(s) read, "
            f"{result.skipped} unrecognised). The file may be empty, or in a format "
            "this tool does not understand. Supported: JSON lines, logback/log4j, "
            "syslog, nginx error logs, and bracketed formats."
        )

    if len(_CACHE) >= _CACHE_LIMIT:
        _CACHE.clear()
    _CACHE[key] = result
    return result


def _load_notes(result: LoadResult) -> list[str]:
    """Caveats about the read itself that the model should know about."""
    notes = []
    if result.truncated:
        notes.append(
            f"This file is larger than the {len(result.entries)}-entry limit; "
            "analysis covers only the entries read so far, from the start of the file."
        )
    if result.skipped:
        share = result.skipped / result.total_lines * 100 if result.total_lines else 0
        notes.append(
            f"{result.skipped} of {result.total_lines} lines ({share:.0f}%) could not "
            "be parsed and are excluded from these numbers."
        )
    return notes


def _stamp(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "unknown"


# --------------------------------------------------------------------------
# summarize_logs
# --------------------------------------------------------------------------


class SummarizeArgs(BaseModel):
    file_path: str = Field(description="Path to the log file to summarize.")


@tool(args_schema=SummarizeArgs)
def summarize_logs(file_path: str) -> str:
    """Get an overall picture of a log file before drilling into specifics.

    Returns entry counts per level, a per-service breakdown showing which
    services are producing errors, the time span covered, and the overall
    error rate. Start here when asked to analyze or assess a log file.
    """
    try:
        result = _load(file_path)
    except _LoadError as exc:
        return str(exc)

    s = analysis.summarize(result.entries, result.skipped)

    lines = [
        f"Log file: {file_path}  (format: {result.format_summary})",
        f"Entries parsed: {s.total}",
        f"Time range: {_stamp(s.first_seen)} to {_stamp(s.last_seen)}"
        + (f" (span {s.duration})" if s.duration else ""),
        f"Error rate: {s.error_rate:.1f}% ({s.failures} of {s.total})",
        "",
        "Counts by level:",
    ]
    for level, count in sorted(s.by_level.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {level:<8} {count}")

    lines += ["", "By service (services with failures first):"]
    ordered = sorted(
        s.by_service.items(),
        key=lambda kv: (-(kv[1].get("ERROR", 0) + kv[1].get("FATAL", 0)), kv[0]),
    )
    for service, levels in ordered:
        detail = " ".join(f"{lvl}={n}" for lvl, n in sorted(levels.items()))
        lines.append(f"  {service:<24} {detail}")

    for note in _load_notes(result):
        lines += ["", f"Note: {note}"]

    return "\n".join(lines)


# --------------------------------------------------------------------------
# search_logs
# --------------------------------------------------------------------------


class SearchArgs(BaseModel):
    file_path: str = Field(description="Path to the log file to search.")
    level: str | None = Field(
        default=None,
        description="Filter by level: DEBUG, INFO, WARN, ERROR or FATAL. "
        "ERROR also returns FATAL entries.",
    )
    service: str | None = Field(
        default=None, description="Filter by service name (substring match)."
    )
    pattern: str | None = Field(
        default=None,
        description="Case-insensitive regular expression matched against the message.",
    )
    trace_id: str | None = Field(default=None, description="Filter to one trace id.")
    limit: int = Field(default=25, description="Maximum entries to return (max 100).")


@tool(args_schema=SearchArgs)
def search_logs(
    file_path: str,
    level: str | None = None,
    service: str | None = None,
    pattern: str | None = None,
    trace_id: str | None = None,
    limit: int = 25,
) -> str:
    """Retrieve the actual log entries matching a filter.

    Use this to read real log lines rather than reasoning about counts — for
    example every ERROR, everything from one service, or every line mentioning
    'timeout'. Filters combine with AND. Returns the matching entries verbatim.
    """
    try:
        result = _load(file_path)
    except _LoadError as exc:
        return str(exc)

    try:
        matches, total = analysis.search(
            result.entries,
            level=level,
            service=service,
            pattern=pattern,
            trace_id=trace_id,
            limit=min(max(limit, 1), MAX_RETURNED_ENTRIES),
        )
    except Exception as exc:  # a bad regex from the model shouldn't kill the run
        return f"Invalid search: {exc}"

    if not matches:
        return "No entries matched those filters."

    header = f"{total} match(es)"
    if len(matches) < total:
        header += f", showing first {len(matches)}"

    body = [entry.one_line() for entry in matches]
    return header + ":\n" + "\n".join(body)


# --------------------------------------------------------------------------
# top_errors
# --------------------------------------------------------------------------


class TopErrorsArgs(BaseModel):
    file_path: str = Field(description="Path to the log file to analyze.")
    limit: int = Field(default=10, description="How many error groups to return.")


@tool(args_schema=TopErrorsArgs)
def top_errors(file_path: str, limit: int = 10) -> str:
    """Find recurring failures by grouping similar errors together.

    Errors that differ only in ids, hostnames, or durations are collapsed into
    one group, so a fault hitting many hosts shows up as a single high-count
    pattern instead of many unrelated-looking lines. Use this to identify what
    is actually going wrong, ranked by frequency.
    """
    try:
        result = _load(file_path)
    except _LoadError as exc:
        return str(exc)

    groups = analysis.top_errors(result.entries, limit=limit)
    if not groups:
        return "No ERROR or FATAL entries in this log."

    lines = [f"{len(groups)} distinct error pattern(s), most frequent first:", ""]
    for i, group in enumerate(groups, start=1):
        lines.append(f"{i}. [{group.count}x] {group.signature}")
        lines.append(f"   services: {', '.join(group.services) or 'unknown'}")
        if group.exceptions:
            lines.append(f"   exception: {'; '.join(group.exceptions)}")
        lines.append(f"   first: {_stamp(group.first_seen)}  last: {_stamp(group.last_seen)}")
        lines.append(f"   example: {group.example.message}")
        if group.example.trace_id:
            lines.append(f"   trace_id: {group.example.trace_id}")
        lines.append("")

    return "\n".join(lines).rstrip()


# --------------------------------------------------------------------------
# trace_timeline
# --------------------------------------------------------------------------


class TraceArgs(BaseModel):
    file_path: str = Field(description="Path to the log file.")
    trace_id: str = Field(
        description="The trace id to reconstruct. Get one from search_logs or "
        "top_errors output."
    )


@tool(args_schema=TraceArgs)
def trace_timeline(file_path: str, trace_id: str) -> str:
    """Reconstruct a single request as it moved across services, in time order.

    This is the strongest tool for root cause analysis: it shows the ordered
    hops of one request, the elapsed time between each, and where it failed.
    Use it after finding a trace_id on an error to understand what led up to
    that failure.
    """
    try:
        result = _load(file_path)
    except _LoadError as exc:
        return str(exc)

    steps = analysis.trace_timeline(result.entries, trace_id)
    if not steps:
        known = sorted({e.trace_id for e in result.entries if e.trace_id})[:10]
        hint = f" Known trace ids include: {', '.join(known)}" if known else ""
        return f"No entries with trace_id '{trace_id}'.{hint}"

    stamps = [s.entry.timestamp for s in steps if s.entry.timestamp]
    span = (max(stamps) - min(stamps)).total_seconds() if len(stamps) > 1 else 0.0

    lines = [
        f"Trace {trace_id}: {len(steps)} step(s) across "
        f"{len({s.entry.service for s in steps})} service(s), spanning {span:.3f}s",
        "",
    ]
    for step in steps:
        gap = f"+{step.gap_ms:>8.0f}ms" if step.gap_ms is not None else "   start   "
        marker = "  <-- FAILURE" if step.entry.is_failure else ""
        lines.append(f"{gap}  {step.entry.one_line()}{marker}")

    slowest = max((s for s in steps if s.gap_ms), key=lambda s: s.gap_ms, default=None)
    if slowest:
        lines += [
            "",
            f"Largest gap: {slowest.gap_ms:.0f}ms before "
            f"{slowest.entry.service} — {slowest.entry.message}",
        ]

    return "\n".join(lines)


# --------------------------------------------------------------------------
# detect_anomalies
# --------------------------------------------------------------------------


class AnomalyArgs(BaseModel):
    file_path: str = Field(description="Path to the log file to analyze.")
    bucket_seconds: int = Field(
        default=60, description="Size of each time bucket, in seconds."
    )


@tool(args_schema=AnomalyArgs)
def detect_anomalies(file_path: str, bucket_seconds: int = 60) -> str:
    """Find error-rate spikes over time and unusually slow operations.

    Buckets the log by time to show when failures clustered, flags buckets
    above the normal failure rate, and reports latency outliers from any
    entries carrying latency_ms. Says explicitly when there is too little data
    to draw a conclusion.
    """
    try:
        loaded = _load(file_path)
    except _LoadError as exc:
        return str(exc)

    result = analysis.detect_anomalies(
        loaded.entries, bucket_seconds=max(bucket_seconds, 1)
    )
    lines: list[str] = []

    if result.buckets:
        lines.append(f"Activity per {bucket_seconds}s bucket (total / failures):")
        for start, total, fails in result.buckets:
            bar = "#" * min(fails, 20)
            flag = "  <-- spike" if (start, fails) in result.spike_buckets else ""
            lines.append(
                f"  {start.strftime('%H:%M:%S')}  {total:>4} / {fails:<3} {bar}{flag}"
            )
        lines.append("")

    if result.spike_buckets:
        lines.append(
            "Error spikes at: "
            + ", ".join(f"{s.strftime('%H:%M:%S')} ({n} failures)" for s, n in result.spike_buckets)
        )
        lines.append("")

    if result.worst_services:
        lines.append("Services by failure count:")
        for service, count in result.worst_services:
            lines.append(f"  {service:<24} {count}")
        lines.append("")

    if result.latency_outliers:
        lines.append(
            f"Slowest operations (at or above the {result.latency_threshold_ms:.0f}ms "
            "95th percentile):"
        )
        for entry in result.latency_outliers[:10]:
            lines.append(f"  {entry.latency_ms:>8.0f}ms  {entry.service} — {entry.message}")
        lines.append("")

    for note in result.notes + _load_notes(loaded):
        lines.append(f"Note: {note}")

    return "\n".join(lines).strip() or "Nothing notable found."


TOOLS = [summarize_logs, search_logs, top_errors, trace_timeline, detect_anomalies]
