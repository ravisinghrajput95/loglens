"""Analysis primitives. Pure functions over lists of LogEntry."""

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .drain import DrainTree
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


# Numbers that carry meaning rather than noise. An HTTP 503 is an upstream
# outage, a 404 is a bad route and a 429 is throttling; collapsing them to
# "HTTP <N>" merges three different incidents into one pattern. The same goes
# for exit codes and signals.
_MEANINGFUL_NUMBER = re.compile(
    r"\b(?:http|https|status(?:[ _-]?code)?|code|response|exit(?:[ _-]?code)?|"
    r"signal|errno)\b\W{0,3}(\d{1,3})\b",
    re.I,
)
_KEEP = "\x00KEEP{}\x00"

# A bucket must sit this many scaled MADs above the median to count as a spike.
# Three is the usual robust-statistics choice: high enough that routine
# variation does not trip it, low enough to catch a real burst.
SPIKE_THRESHOLD_MADS = 3.0

# Below this many buckets the median and MAD are not meaningful.
MIN_BUCKETS_FOR_SPIKES = 5


def signature(message: str) -> str:
    """Collapse the variable parts of a message so equivalent errors group.

    'Connection timeout after 5000ms to postgres-01' and
    'Connection timeout after 3000ms to postgres-04' both become
    'Connection timeout after <N>ms to <NAME>'.

    Status and exit codes are held back from that collapsing, because they
    distinguish failures rather than describing the same one.
    """
    kept: list[str] = []

    def hold(match: re.Match) -> str:
        kept.append(match.group(1))
        return match.group(0).replace(match.group(1), _KEEP.format(len(kept) - 1))

    text = _MEANINGFUL_NUMBER.sub(hold, message)
    for pattern, placeholder in _NOISE_PATTERNS:
        text = pattern.sub(placeholder, text)
    for index, value in enumerate(kept):
        text = text.replace(_KEEP.format(index), value)

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


# Nested quantifiers are what turn a regex into a hang: (a+)+ against a long
# non-matching string backtracks exponentially. Python's re has no timeout and
# a catastrophic match holds the GIL, so it cannot be cancelled from another
# thread — the pattern has to be refused before it runs.
_NESTED_QUANTIFIER = re.compile(r"[)\]]\s*[*+]|\([^)]*[*+][^)]*\)\s*[*+{]")
_MAX_PATTERN_LENGTH = 200

# Longest single line handed to a user-supplied regex. A pathological pattern
# costs time proportional to input length; bounding the input bounds the harm.
_MAX_MATCH_LENGTH = 4_000


class UnsafePattern(ValueError):
    """Raised for a regex that could take unbounded time to evaluate."""


def compile_pattern(pattern: str) -> re.Pattern:
    """Compile a search pattern, refusing shapes that can hang the process."""
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise UnsafePattern(
            f"pattern is {len(pattern)} characters; the limit is {_MAX_PATTERN_LENGTH}"
        )
    if _NESTED_QUANTIFIER.search(pattern):
        raise UnsafePattern(
            "pattern nests one repetition inside another, e.g. (a+)+, which can "
            "take exponential time. Rewrite it without the nested repetition."
        )
    return re.compile(pattern, re.IGNORECASE)


def in_window(
    entries: list[LogEntry],
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[LogEntry]:
    """Restrict to a time window.

    Entries without a timestamp are dropped when a window is given: including
    them would silently mix unplaceable events into a bounded question.
    """
    if since is None and until is None:
        return entries
    kept = []
    for entry in entries:
        if entry.timestamp is None:
            continue
        if since and entry.timestamp < since:
            continue
        if until and entry.timestamp > until:
            continue
        kept.append(entry)
    return kept


def search(
    entries: list[LogEntry],
    level: str | None = None,
    service: str | None = None,
    pattern: str | None = None,
    trace_id: str | None = None,
    limit: int = 50,
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[list[LogEntry], int]:
    """Filter entries. Returns the capped results and the total match count."""
    matches = in_window(entries, since, until)

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
        regex = compile_pattern(pattern)
        matches = [
            e
            for e in matches
            if regex.search(e.message[:_MAX_MATCH_LENGTH])
            or regex.search(e.raw[:_MAX_MATCH_LENGTH])
        ]

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
    """Group failures into learned templates, most frequent first.

    Grouping is done by Drain rather than by the fixed regexes in signature().
    The regexes could only collapse variable shapes somebody had anticipated;
    Drain discovers which token positions vary from the messages themselves,
    so it groups 'Failed password for root' with 'Failed password for admin'
    without anyone having declared that usernames are variable.
    """
    tree = DrainTree()
    groups: dict[int, list[LogEntry]] = defaultdict(list)
    templates: dict[int, object] = {}

    for entry in entries:
        if entry.is_failure:
            template = tree.add(entry.message)
            groups[id(template)].append(entry)
            templates[id(template)] = template

    result = []
    for key, members in groups.items():
        sig = templates[key].text
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
    if len(buckets) < MIN_BUCKETS_FOR_SPIKES:
        notes.append(
            f"Only {len(buckets)} time bucket(s) of {bucket_seconds}s — at least "
            f"{MIN_BUCKETS_FOR_SPIKES} are needed before a burst can be told apart "
            "from ordinary variation."
        )
    elif any(failure_counts):
        # Median absolute deviation rather than mean and standard deviation.
        # Log arrivals are bursty and far from normal, and a spike drags the
        # mean up towards itself — so mean+sigma partly hides the event it is
        # meant to find, while flagging ordinary variation the rest of the
        # time. MAD is unmoved by a minority of extreme values.
        median = statistics.median(failure_counts)
        mad = statistics.median([abs(count - median) for count in failure_counts])
        scale = mad * 1.4826  # rescale so the threshold is sigma-comparable

        if scale == 0:
            # Every bucket is identical, so MAD cannot express a distance.
            # Anything above that flat baseline is the anomaly.
            spikes = [(start, fails) for start, _, fails in buckets if fails > median]
        else:
            spikes = [
                (start, fails)
                for start, _, fails in buckets
                if fails > median and (fails - median) / scale >= SPIKE_THRESHOLD_MADS
            ]

        if not spikes:
            notes.append(
                "Failures are spread evenly rather than clustered — no bucket "
                "stands out from the baseline."
            )

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
