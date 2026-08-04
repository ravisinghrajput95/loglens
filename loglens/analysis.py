"""Analysis primitives. Pure functions over lists of LogEntry."""

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import FAILURE_LEVELS, LogEntry

# Patterns whose matches are replaced before grouping errors together, so that
# two messages differing only in an id or a duration collapse to one signature.
_NOISE_PATTERNS = (
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<ID>"),
    (re.compile(r"\b\w+-\w*\d[\w-]*\b"), "<NAME>"),
    # No trailing \b: a number glued to its unit ("5000ms", "512MB") has no word
    # boundary after the digits, and those are exactly the values that vary.
    (re.compile(r"\b\d+(?:\.\d+)?"), "<N>"),
)


def signature(message: str) -> str:
    """Collapse the variable parts of a message so equivalent errors group.

    'Connection timeout after 5000ms to postgres-01' and
    'Connection timeout after 3000ms to postgres-04' both become
    'Connection timeout after <N>ms to <NAME>'.
    """
    text = message
    for pattern, placeholder in _NOISE_PATTERNS:
        text = pattern.sub(placeholder, text)
    return re.sub(r"\s+", " ", text).strip()


@dataclass
class Summary:
    total: int
    skipped: int
    by_level: dict[str, int]
    by_service: dict[str, Counter]
    first_seen: datetime | None
    last_seen: datetime | None

    @property
    def failures(self) -> int:
        return sum(self.by_level.get(level, 0) for level in FAILURE_LEVELS)

    @property
    def error_rate(self) -> float:
        return (self.failures / self.total * 100) if self.total else 0.0

    @property
    def duration(self) -> timedelta | None:
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return None


def summarize(entries: list[LogEntry], skipped: int = 0) -> Summary:
    """Overall shape of the log: level counts, per-service breakdown, span."""
    by_level: Counter = Counter()
    by_service: dict[str, Counter] = defaultdict(Counter)

    for entry in entries:
        by_level[entry.level] += 1
        by_service[entry.service or "unknown"][entry.level] += 1

    stamps = [e.timestamp for e in entries if e.timestamp]
    return Summary(
        total=len(entries),
        skipped=skipped,
        by_level=dict(by_level),
        by_service=dict(by_service),
        first_seen=min(stamps) if stamps else None,
        last_seen=max(stamps) if stamps else None,
    )


def search(
    entries: list[LogEntry],
    level: str | None = None,
    service: str | None = None,
    pattern: str | None = None,
    trace_id: str | None = None,
    limit: int = 50,
) -> tuple[list[LogEntry], int]:
    """Filter entries. Returns the capped results and the total match count."""
    matches = entries

    if level:
        wanted = level.strip().upper()
        # "ERROR" should surface FATAL too — nobody investigating errors wants
        # the more severe ones hidden.
        levels = set(FAILURE_LEVELS) if wanted == "ERROR" else {wanted}
        matches = [e for e in matches if e.level in levels]

    if service:
        needle = service.lower()
        matches = [e for e in matches if e.service and needle in e.service.lower()]

    if trace_id:
        matches = [e for e in matches if e.trace_id == trace_id]

    if pattern:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = [e for e in matches if regex.search(e.message) or regex.search(e.raw)]

    return matches[:limit], len(matches)


@dataclass
class ErrorGroup:
    signature: str
    count: int
    services: list[str]
    example: LogEntry
    exceptions: list[str]
    first_seen: datetime | None
    last_seen: datetime | None


def top_errors(entries: list[LogEntry], limit: int = 10) -> list[ErrorGroup]:
    """Group failures by normalized message, most frequent first."""
    groups: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.is_failure:
            groups[signature(entry.message)].append(entry)

    result = []
    for sig, members in groups.items():
        stamps = [m.timestamp for m in members if m.timestamp]
        result.append(
            ErrorGroup(
                signature=sig,
                count=len(members),
                services=sorted({m.service for m in members if m.service}),
                example=members[0],
                exceptions=sorted({m.exception for m in members if m.exception}),
                first_seen=min(stamps) if stamps else None,
                last_seen=max(stamps) if stamps else None,
            )
        )

    result.sort(key=lambda g: g.count, reverse=True)
    return result[:limit]


@dataclass
class TraceStep:
    entry: LogEntry
    gap_ms: float | None  # time since the previous step in the trace


def trace_timeline(entries: list[LogEntry], trace_id: str) -> list[TraceStep]:
    """Reconstruct one request across services, ordered in time.

    The gap between consecutive steps is where latency actually went, which is
    usually what identifies the failing hop.
    """
    members = [e for e in entries if e.trace_id == trace_id]
    members.sort(key=lambda e: (e.timestamp is None, e.timestamp, e.line_no))

    steps = []
    previous: datetime | None = None
    for entry in members:
        gap = None
        if entry.timestamp and previous:
            gap = (entry.timestamp - previous).total_seconds() * 1000
        steps.append(TraceStep(entry=entry, gap_ms=gap))
        if entry.timestamp:
            previous = entry.timestamp

    return steps


@dataclass
class Anomalies:
    buckets: list[tuple[datetime, int, int]]  # bucket start, total, failures
    spike_buckets: list[tuple[datetime, int]]
    latency_outliers: list[LogEntry]
    latency_threshold_ms: float | None
    worst_services: list[tuple[str, int]]
    notes: list[str]


def detect_anomalies(
    entries: list[LogEntry],
    bucket_seconds: int = 60,
    latency_percentile: float = 95.0,
) -> Anomalies:
    """Look for error spikes and slow operations.

    Both checks need enough data to mean anything, so when there isn't enough
    we say so in `notes` rather than reporting noise as a finding.
    """
    notes: list[str] = []

    # --- error rate over time ---
    counts: dict[datetime, list[int]] = {}
    stamped = [e for e in entries if e.timestamp]
    for entry in stamped:
        epoch = int(entry.timestamp.timestamp())
        start = datetime.fromtimestamp(
            epoch - (epoch % bucket_seconds), tz=entry.timestamp.tzinfo
        )
        slot = counts.setdefault(start, [0, 0])
        slot[0] += 1
        slot[1] += 1 if entry.is_failure else 0

    buckets = [(start, total, fails) for start, (total, fails) in sorted(counts.items())]

    spikes: list[tuple[datetime, int]] = []
    failure_counts = [fails for _, _, fails in buckets]
    if len(buckets) < 3:
        notes.append(
            f"Only {len(buckets)} time bucket(s) of {bucket_seconds}s — "
            "too few to judge whether error rate is spiking."
        )
    elif any(failure_counts):
        mean = statistics.mean(failure_counts)
        spread = statistics.pstdev(failure_counts)
        threshold = mean + spread
        spikes = [
            (start, fails) for start, _, fails in buckets if fails > threshold and fails > 0
        ]

    # --- latency outliers ---
    timed = [e for e in entries if e.latency_ms is not None]
    outliers: list[LogEntry] = []
    cutoff: float | None = None
    if len(timed) < 5:
        notes.append(
            f"Only {len(timed)} entries carry latency_ms — not enough to establish a baseline."
        )
    else:
        values = sorted(e.latency_ms for e in timed)
        index = min(int(len(values) * latency_percentile / 100), len(values) - 1)
        cutoff = values[index]
        outliers = sorted(
            (e for e in timed if e.latency_ms >= cutoff),
            key=lambda e: e.latency_ms,
            reverse=True,
        )

    # --- which services are failing most ---
    failing: Counter = Counter(e.service or "unknown" for e in entries if e.is_failure)

    return Anomalies(
        buckets=buckets,
        spike_buckets=spikes,
        latency_outliers=outliers,
        latency_threshold_ms=cutoff,
        worst_services=failing.most_common(5),
        notes=notes,
    )
