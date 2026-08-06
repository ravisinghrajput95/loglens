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
    "%y%m%d %H%M%S",  # HDFS: 081109 203615
    "%y/%m/%d %H:%M:%S",  # Spark, Hadoop: 17/06/09 20:10:40
    "%Y/%m/%d - %H:%M:%S",  # Gin access log
    "%a %b %d %H:%M:%S %Y",  # Apache error log: Sun Dec 04 04:47:44 2005
    "%a %b %d %H:%M:%S.%f %Y",
    "%Y%m%d-%H:%M:%S:%f",  # HealthApp: 20171223-22:15:29:606
    "%Y-%m-%d %H:%M:%S.%f %z",
    "%Y-%m-%d %H:%M:%S%z",  # macOS install.log: ...41-07
)

# Syslog omits the year. Parsing it yearless is deprecated from Python 3.15,
# so the current year is prepended before parsing rather than patched in after.
_YEARLESS_FORMATS = (
    ("%b %d %H:%M:%S", "%Y %b %d %H:%M:%S"),
    ("%m.%d %H:%M:%S", "%Y %m.%d %H:%M:%S"),  # Proxifier: 10.30 16:49:06
)

# A two-digit UTC offset like "-07" is not something strptime accepts, but
# macOS writes it. Widen it to "-0700" before parsing.
_SHORT_OFFSET = re.compile(r"([+-]\d{2})$")


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

    widened = _SHORT_OFFSET.sub(r"\g<1>00", text)
    if widened != text:
        try:
            return _as_aware(datetime.fromisoformat(widened))
        except ValueError:
            pass
        text = widened

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
            r"(?P<service>[\w./()-]+(?:\s+[\d.]+)?)"
            r"(?:\[(?P<pid>\d+)\])?(?:\s*\([^)]*\))?:\s*"
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
        # Spark, Hadoop, and most JVM tools:
        #   17/06/09 20:10:40 INFO executor.CoarseGrained: message
        "spark",
        re.compile(
            r"^(?P<timestamp>\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
            rf"(?P<level>{_LEVEL_WORDS})\s+"
            r"(?P<service>[\w.$]+):\s*(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # HDFS:
        #   081109 203615 148 INFO dfs.DataNode$PacketResponder: message
        "hdfs",
        re.compile(
            r"^(?P<timestamp>\d{6} \d{6})\s+(?P<pid>\d+)\s+"
            rf"(?P<level>{_LEVEL_WORDS})\s+"
            r"(?P<service>[\w.$]+):\s*(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # OpenStack, which prefixes each line with its source file:
        #   nova-api.log.1.2017-05-16 2017-05-16 00:00:00.008 25746 INFO nova.x [req-..] message
        "openstack",
        re.compile(
            r"^\S+\.log\S*\s+"
            r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"(?P<pid>\d+)\s+"
            rf"(?P<level>{_LEVEL_WORDS})\s+"
            r"(?P<service>[\w.-]+)\s*(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ),
    (
        # macOS install.log and similar:
        #   2026-06-03 10:52:41-07 localhost Installer Progress[57]: message
        "macos",
        re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[+-]\d{2,4})?)\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>[\w .()/-]+?)\[(?P<pid>\d+)\]"
            r"(?:\s*\([^)]*\))?:\s*(?P<message>.*)$"
        ),
    ),
    (
        # Thunderbird / BGL supercomputer logs:
        #   - 1131566461 2005.11.09 dn228 Nov 9 12:01:01 dn228/dn228 crond[2915]: message
        "bgl",
        re.compile(
            r"^(?P<flag>-|[A-Z]\S*)\s+\d{9,}\s+\d{4}\.\d{2}\.\d{2}\s+\S+\s+"
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>[\w./()-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
        ),
    ),
    (
        # Gin (Go HTTP framework) access log:
        #   [GIN] 2026/07/30 - 23:07:31 | 200 | 209.291µs | 127.0.0.1 | GET "/api/version"
        "gin",
        re.compile(
            r"^\[GIN\]\s+(?P<timestamp>\d{4}/\d{2}/\d{2} - \d{2}:\d{2}:\d{2})\s*\|"
            r"\s*(?P<status>\d{3})\s*\|"
            r"\s*(?P<took>\S+)\s*\|"
            r"\s*(?P<client>\S+)\s*\|"
            r"\s*(?P<message>.*)$"
        ),
    ),
    (
        # Proxifier:
        #   [10.30 16:49:06] chrome.exe - proxy.example:5070 open through proxy
        "proxifier",
        re.compile(
            r"^\[(?P<timestamp>\d{2}\.\d{2} \d{2}:\d{2}:\d{2})\]\s+"
            r"(?P<service>\S+(?:\s+\*\d+)?)\s+-\s+(?P<message>.*)$"
        ),
    ),
    (
        # Pipe-delimited, as HealthApp and many mobile SDKs emit:
        #   20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579
        "pipe",
        re.compile(
            r"^(?P<timestamp>\d{8}-\d{2}:\d{2}:\d{2}:\d{1,3})\|"
            r"(?P<service>[^|]*)\|(?P<pid>[^|]*)\|(?P<message>.*)$"
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

# The kubelet writes an RFC3339Nano timestamp, the stream, and a full/partial
# tag before the container's own output:
#   2026-08-05T10:00:01.123456789Z stdout F Server listening on port 8080
# `kubectl logs --timestamps` produces the same prefix without the stream.
_CRI_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r"(?:\s+(?P<stream>stdout|stderr)(?:\s+(?P<tag>[PF]))?)?\s+(?P<rest>.*)$"
)


def parse_container_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Strip a kubelet timestamp prefix and parse what the container wrote.

    The prefix is the kubelet's, not the application's. Discarding it and
    re-parsing the remainder means a JSON or logback line keeps its own fields
    instead of being reduced to opaque text after a timestamp.
    """
    match = _CRI_PREFIX.match(line)
    if not match:
        return None

    rest = match.group("rest").strip()
    if not rest:
        return None

    inner = parse_json_line(rest, line_no) or parse_logfmt_line(rest, line_no)
    if inner is None:
        inner, _ = parse_text_line(rest, line_no)

    stamp = parse_timestamp(match.group("timestamp"))
    if inner is not None:
        # The container's own timestamp is better than the kubelet's, but the
        # kubelet's is better than none.
        inner.timestamp = inner.timestamp or stamp
        inner.raw = line
        if match.group("stream") == "stderr" and inner.level == "UNKNOWN":
            inner.level = "ERROR"
        return inner

    return LogEntry(
        line_no=line_no,
        raw=line,
        # stderr is where containers put failures, and it is a field the
        # runtime recorded rather than a guess about wording.
        level="ERROR" if match.group("stream") == "stderr" else "UNKNOWN",
        timestamp=stamp,
        message=rest,
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


# Cloud log platforms wrap a message in an envelope and capitalise their keys.
# Azure writes LogMessage and TimeGenerated, Google nests the payload under
# jsonPayload or textPayload and the container name under resource.labels.
# Matching case-sensitively on top-level keys finds none of it.
# Azure's LogMessage is a dynamic column: when the container writes JSON it
# arrives as an object rather than a string, and rendering that with str()
# produces a Python dict repr with the fields still buried in it.
_NESTED_PAYLOADS = (
    "jsonPayload",
    "structPayload",
    "protoPayload",
    "fields",
    "data",
    "LogMessage",
    "log",
)


def _flatten(payload: dict[str, Any]) -> dict[str, Any]:
    """Lift nested cloud-envelope fields to the top level, without clobbering.

    Only the shapes these platforms actually use are unwrapped, and an outer
    key always wins: an envelope should not overwrite what the application
    itself recorded.
    """
    flat = dict(payload)

    for key in _NESTED_PAYLOADS:
        inner = payload.get(key)

        # A dynamic column survives export as a JSON-encoded string. Azure's
        # own CLI returns LogMessage that way, so an application's structured
        # log arrives as text and its trace id is invisible — which silently
        # disables trace reconstruction on the entire ingestion path.
        if isinstance(inner, str):
            text = inner.strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    inner = json.loads(text)
                except ValueError:
                    inner = None

        if isinstance(inner, dict):
            for k, v in inner.items():
                flat.setdefault(k, v)

    # Google Cloud Logging carries the pod and container under resource.labels.
    resource = payload.get("resource")
    if isinstance(resource, dict):
        labels = resource.get("labels")
        if isinstance(labels, dict):
            for k, v in labels.items():
                flat.setdefault(k, v)

    return flat


def _as_message(value: Any) -> str:
    """Render a message field as text.

    A dynamic column can hand back an object. Rendering that with str() gives
    a Python repr — single quotes, True instead of true — which is neither the
    original line nor valid JSON. Serialising it keeps it searchable.
    """
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return str(value).rstrip("\n")


def _audit_event(payload: dict[str, Any]) -> dict[str, str] | None:
    """Render a Kubernetes audit event as something a person can read.

    EKS, AKS and GKE all ship control-plane audit logs, and they carry no
    message field at all — the event is spread across verb, requestURI and
    responseStatus. Left alone every entry parses as an empty message, which
    is exactly the shape that hides an RBAC denial.
    """
    if not str(payload.get("apiVersion", "")).startswith("audit.k8s.io"):
        return None

    status = payload.get("responseStatus")
    code = status.get("code") if isinstance(status, dict) else None
    user = payload.get("user")
    username = user.get("username") if isinstance(user, dict) else None

    parts = [str(payload.get("verb") or "?"), str(payload.get("requestURI") or "?")]
    if code is not None:
        parts.append(f"-> {code}")
    if username:
        parts.append(f"(user {username})")

    level = "UNKNOWN"
    if isinstance(code, int):
        # The response code is the outcome the API server recorded. A 403 on a
        # control-plane call is usually the thing being looked for.
        level = "ERROR" if code >= 500 else "WARN" if code >= 400 else "INFO"

    return {"message": " ".join(parts), "level": level}


def _first(payload: dict[str, Any], *keys: str) -> Any:
    """First key present, matched without regard to case or separators."""
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]

    folded = {k.lower().replace("_", "").replace("-", ""): v for k, v in payload.items()}
    for key in keys:
        value = folded.get(key.lower().replace("_", "").replace("-", ""))
        if value is not None:
            return value
    return None


# logfmt: space-separated key=value, values optionally quoted. Emitted by most
# of the Go ecosystem — Docker, Grafana, Loki, Ollama — so it is worth parsing
# properly rather than leaving to the loose fallback.
_LOGFMT_PAIR = re.compile(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)')
_LOGFMT_LIKELY = re.compile(r"(?:^|\s)(?:time|ts|level|lvl|msg|message)=")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def parse_logfmt_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Parse a logfmt line: time=... level=INFO msg="..." key=value."""
    if not _LOGFMT_LIKELY.search(line):
        return None

    pairs = {k: _unquote(v) for k, v in _LOGFMT_PAIR.findall(line)}
    if not pairs or not ({"msg", "message", "level", "lvl"} & pairs.keys()):
        return None

    latency = pairs.get("duration_ms") or pairs.get("latency_ms")
    try:
        latency_value = float(latency) if latency else None
    except ValueError:
        latency_value = None

    known = {
        "time",
        "ts",
        "timestamp",
        "level",
        "lvl",
        "msg",
        "message",
        "source",
        "service",
        "component",
        "logger",
        "host",
        "trace_id",
        "err",
        "error",
        "duration_ms",
        "latency_ms",
    }
    return LogEntry(
        line_no=line_no,
        raw=line,
        level=normalize_level(pairs.get("level") or pairs.get("lvl")),
        timestamp=parse_timestamp(
            pairs.get("time") or pairs.get("ts") or pairs.get("timestamp")
        ),
        service=pairs.get("service") or pairs.get("component") or pairs.get("source"),
        host=pairs.get("host"),
        message=pairs.get("msg") or pairs.get("message") or "",
        trace_id=pairs.get("trace_id"),
        exception=pairs.get("err") or pairs.get("error"),
        latency_ms=latency_value,
        extra={k: v for k, v in pairs.items() if k not in known},
    )


def parse_json_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Parse one JSON object line."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None

    payload = _flatten(payload)
    audit = _audit_event(payload)

    latency = _first(payload, "latency_ms", "duration_ms", "elapsed_ms")
    # A kubernetes audit event's "level" is its verbosity (Metadata, Request),
    # not a severity, and reading it as one would label every audited call.
    level_value = _first(payload, "level", "severity", "loglevel")
    if audit:
        level_value = audit["level"]
    elif level_value is None and _first(payload, "stream", "logsource") == "stderr":
        # The container runtime recorded which stream this came from. Reading
        # stderr as a failure uses a field that exists rather than guessing
        # from wording.
        level_value = "ERROR"

    return LogEntry(
        line_no=line_no,
        raw=line,
        level=normalize_level(level_value),
        timestamp=parse_timestamp(
            _first(
                payload,
                "timestamp",
                "time",
                "@timestamp",
                "ts",
                "timegenerated",
                "requestReceivedTimestamp",
            )
        ),
        service=_first(
            payload,
            "service",
            "logger",
            "containername",
            "container_name",
            "logstreamname",
            "unit",
        ),
        host=_first(payload, "host", "hostname", "computer", "node_name", "podname"),
        message=(
            audit["message"]
            if audit
            else _as_message(
                _first(payload, "message", "msg", "logmessage", "textpayload", "log")
            )
        ),
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

        if name == "gin":
            service = service or "gin"
            # An access log states its outcome as a status code. Reading 500 as
            # an error is interpreting the field that exists, not inventing a
            # severity the line never carried.
            status = groups.get("status")
            if status and status.isdigit():
                code = int(status)
                level = "ERROR" if code >= 500 else "WARN" if code >= 400 else "INFO"

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


# Wording that states an outcome. Used only when a log format carries no
# severity field at all, and only when explicitly asked for: syslog, Proxifier
# and similar formats otherwise report a 0% error rate on a file full of
# failures, which is worse than saying nothing.
_SEVERITY_HINTS: tuple[tuple[str, re.Pattern], ...] = (
    (
        "ERROR",
        re.compile(
            r"\b(?:fail(?:ed|ure|s)?|error|denied|refused|reject(?:ed)?|timed?\s*out|"
            r"timeout|unable to|cannot|can't|couldn't|exception|panic|fatal|"
            r"corrupt(?:ed)?|unauthori[sz]ed|forbidden|invalid|abort(?:ed)?|"
            r"crash(?:ed)?|no space|out of memory|segfault|not permitted)\b",
            re.I,
        ),
    ),
    (
        "WARN",
        re.compile(
            r"\b(?:warn(?:ing)?|deprecat(?:ed|ion)|retry(?:ing)?|retries|slow|"
            r"throttl(?:ed|ing)|degraded|unstable|exceed(?:ed|s)?|"
            r"nearly full|high usage|disconnect(?:ed)?)\b",
            re.I,
        ),
    ),
)


def infer_level(text: str) -> str:
    """Guess a severity from wording. ERROR wins over WARN when both appear."""
    for level, pattern in _SEVERITY_HINTS:
        if pattern.search(text):
            return level
    return "INFO"


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
        entry = parse_logfmt_line(stripped, line_no)
    if entry is None:
        entry = parse_container_line(stripped, line_no)
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
    def unknown_share(self) -> float:
        """Fraction of entries whose format carried no severity field."""
        if not self.total_entries:
            return 0.0
        return self.total_by_level.get("UNKNOWN", 0) / self.total_entries

    @property
    def has_severity(self) -> bool:
        """Is an error rate meaningful for this file at all?"""
        return self.unknown_share < 0.5

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
                entry = parse_logfmt_line(stripped, line_no)
            if entry is None:
                entry = parse_container_line(stripped, line_no)
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
    infer_severity: bool = False,
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
        if infer_severity and entry.level == "UNKNOWN":
            entry.level = infer_level(entry.message or entry.raw)
            entry.level_inferred = True
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
                entry = parse_logfmt_line(stripped, line_no)
                fmt = "logfmt" if entry is not None else ""
            if entry is None:
                entry = parse_container_line(stripped, line_no)
                fmt = "container" if entry is not None else ""
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


def restrict(result: LoadResult, entries: list[LogEntry]) -> LoadResult:
    """A LoadResult describing only `entries`, with totals recomputed.

    Applying a time window and leaving the whole-file counters in place would
    report a rate for a period the user did not ask about. Counts must always
    describe the same set of entries the report is about.
    """
    by_level: Counter = Counter()
    for entry in entries:
        by_level[entry.level] += 1

    return LoadResult(
        entries=entries,
        total_lines=result.total_lines,
        total_entries=len(entries),
        skipped=result.skipped,
        # A window is an explicit choice, not a limit that was hit.
        truncated=False,
        formats=result.formats,
        total_by_level=by_level,
        redactions=result.redactions,
        suspicious=sum(1 for e in entries if e.suspicious),
    )


def load_many(
    paths: list[str | Path],
    max_entries: int = DEFAULT_MAX_ENTRIES,
    redact_secrets: bool = True,
    infer_severity: bool = False,
) -> LoadResult:
    """Read several logs as one timeline.

    An incident usually spans services, and their logs are usually separate
    files. Merging them in time order is what lets a trace be followed across
    the boundary — the single most useful thing this tool does, and impossible
    while it could only see one file.

    Line numbers repeat across files, so merged entries are renumbered for
    citation. Each entry keeps its file and original line for display.
    """
    if len(paths) == 1:
        return load_entries(paths[0], max_entries, redact_secrets, infer_severity)

    merged: list[LogEntry] = []
    combined = LoadResult(entries=[])

    for path in paths:
        target = Path(path)
        result = load_entries(target, max_entries, redact_secrets, infer_severity)
        for entry in result.entries:
            entry.source = target.name
        merged.extend(result.entries)

        combined.total_lines += result.total_lines
        combined.total_entries += result.total_entries
        combined.skipped += result.skipped
        combined.truncated = combined.truncated or result.truncated
        combined.formats.update(result.formats)
        combined.total_by_level.update(result.total_by_level)
        combined.redactions.update(result.redactions)
        combined.suspicious += result.suspicious

    # Undated entries sort last: they cannot be placed on the timeline, and
    # interleaving them arbitrarily would imply an order that is not known.
    merged.sort(key=lambda e: (e.timestamp is None, e.timestamp, e.source, e.line_no))
    for index, entry in enumerate(merged, start=1):
        entry.uid = index

    combined.entries = merged
    return combined
