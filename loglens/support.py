"""Does the cited line actually say what the claim says it says?

`verify.py` answers referential integrity: the id exists, and it is not
hostile. That leaves the question people assume is being answered — whether
the line *supports* the claim — untouched. A model can cite L12 perfectly and
still describe it backwards, and every existing check passes.

Full entailment needs a model, and a model is exactly what must not be trusted
here; putting one in the verifier would make the check as fallible as the thing
it checks, and would take the offline evals out of CI. So this module answers a
deliberately narrower question, deterministically: are there *mechanical*
contradictions between the claim and the evidence it cites?

That trades recall for precision on purpose. It will never catch every
unsupported claim. It is built so that when it does fire, it is right — a
verifier people switch off is worth less than one that stays quiet.

The first thing any such check needs is the evidence itself: the rendered line
behind each id, pulled back out of the tool output the model was shown. That is
what this half of the module does. Reading it back from the rendered text,
rather than being handed the entries alongside, keeps the check honest — it
sees exactly what the model saw, including a line the renderer truncated.
"""

import re
from dataclasses import dataclass
from datetime import time

# Every id mentioned anywhere in a line of tool output.
_LINE_ID = re.compile(r"\[L(\d+)\]")

# Tools separate one rendered item from the next with a blank line.
_BLOCKS = re.compile(r"\n\s*\n")

# The `models.LogEntry.cite()` rendering:
#   [L12] 20:17:00 ERROR order-service          Failed to publish to Kafka
# Level is padded to 5 and followed by a marker column that is `~` when the
# level was inferred rather than read, so level and service can run together.
_STAMPED = re.compile(
    r"\[L(?P<id>\d+)\]\s+"
    r"(?P<stamp>\d{2}:\d{2}:\d{2}|--:--:--)\s+"
    r"(?P<level>DEBUG|INFO|WARN|ERROR|FATAL)?\s*"
    r"(?P<inferred>~)?\s*"
    r"(?P<rest>.*)$"
)

# The trace-step rendering in `report.py` carries a gap instead of a clock:
#   +   5847ms [L13] WARN  order-service        Circuit breaker OPEN
_LEVELLED = re.compile(
    r"\[L(?P<id>\d+)\]\s+(?P<level>DEBUG|INFO|WARN|ERROR|FATAL)\s+(?P<rest>.*)$"
)

FAILURE_LEVELS = ("ERROR", "FATAL")


@dataclass
class Evidence:
    """One rendered log line, as the model was shown it."""

    line_id: int
    # The whole rendered line, with the leading id marker removed. Support
    # checks read this rather than `message` so that nothing a tool chose to
    # append — an exception name, a SUSPICIOUS marker — falls outside the
    # evidence.
    text: str
    # The blank-line-delimited block this line was rendered inside. Tools put
    # a line's context around it rather than on it: `top_errors` renders the
    # `[47x]` count five lines above the `example: [L12]` it belongs to, so a
    # check that read only `text` would call a correct count invented.
    block: str = ""
    level: str = ""
    service: str = ""
    message: str = ""
    stamp: time | None = None
    level_inferred: bool = False

    @property
    def is_failure(self) -> bool:
        return self.level in FAILURE_LEVELS

    @property
    def has_level(self) -> bool:
        """Was a severity actually read off this line?

        A line rendered without one, or with one the parser guessed from
        wording, cannot settle a claim about whether something failed.
        """
        return bool(self.level) and not self.level_inferred


def _parse_stamp(raw: str) -> time | None:
    if not raw or raw.startswith("--"):
        return None
    try:
        hour, minute, second = (int(part) for part in raw.split(":"))
        return time(hour, minute, second)
    except ValueError:
        return None


def _split_service(rest: str) -> tuple[str, str]:
    """Separate the service column from the message that follows it.

    The renderer pads the service to a fixed width, so one or more spaces
    divide them. A line with neither is treated as all message, never as a
    service with an empty message — a wrong service attribution would be worse
    than none, since later checks compare services by name.
    """
    parts = rest.split(None, 1)
    if len(parts) == 2:
        return parts[0], parts[1].strip()
    return "", rest.strip()


def _parse_line(line: str) -> Evidence | None:
    """Read one rendered line back into structured evidence."""
    stamped = _STAMPED.search(line)
    if stamped:
        service, message = _split_service(stamped.group("rest"))
        return Evidence(
            line_id=int(stamped.group("id")),
            text=line.split("] ", 1)[-1].strip() if "] " in line else line.strip(),
            level=stamped.group("level") or "",
            service=service,
            message=message,
            stamp=_parse_stamp(stamped.group("stamp")),
            level_inferred=bool(stamped.group("inferred")),
        )

    levelled = _LEVELLED.search(line)
    if levelled:
        service, message = _split_service(levelled.group("rest"))
        return Evidence(
            line_id=int(levelled.group("id")),
            text=line.split("] ", 1)[-1].strip() if "] " in line else line.strip(),
            level=levelled.group("level"),
            service=service,
            message=message,
        )

    return None


def index_evidence(sources: list[str]) -> dict[int, Evidence]:
    """Map each cited id to the line the tools rendered for it.

    Ids that appear only in passing — `first at [L12]` inside a pattern
    summary — are recorded with the surrounding line as their text when the id
    has no rendering of its own. A claim citing such an id has *something*
    behind it, and treating that as missing evidence would fire on honest
    answers.
    """
    evidence: dict[int, Evidence] = {}
    mentions: dict[int, tuple[str, str]] = {}

    for source in sources:
        for block in _BLOCKS.split(source):
            for line in block.splitlines():
                ids = [int(m) for m in _LINE_ID.findall(line)]
                if not ids:
                    continue

                parsed = _parse_line(line)
                if parsed is not None:
                    # A structured rendering wins over a passing mention, and
                    # the first one wins over a later repeat: tools list a line
                    # in full before summarising it.
                    parsed.block = block
                    evidence.setdefault(parsed.line_id, parsed)
                    ids = [i for i in ids if i != parsed.line_id]

                for line_id in ids:
                    mentions.setdefault(line_id, (line.strip(), block))

    for line_id, (text, block) in mentions.items():
        if line_id not in evidence:
            evidence[line_id] = Evidence(line_id=line_id, text=text, block=block)

    return evidence


# ---------------------------------------------------------------------------
# Support checks
#
# Each check looks for one mechanical contradiction between a claim and the
# evidence it cites. They share a bias: stay silent unless the conflict is
# unambiguous. A false positive on an honest answer costs more than a miss,
# because it is the thing that gets the whole verifier switched off.
# ---------------------------------------------------------------------------


@dataclass
class Unsupported:
    """One claim that its own citation contradicts."""

    claim: str
    line_ids: tuple[int, ...]
    kind: str
    detail: str


# Words that assert the absence of trouble.
_HEALTH_STATE = re.compile(
    r"\b(?:is|are|was|were|remained?|remains|appears?|seems?|looks?)\s+"
    r"(?P<gap>(?:\w+\s+){0,2}?)"
    r"(?:healthy|fine|normal|nominal|stable|unaffected|operational|uneventful)\b",
    re.I,
)
_ABSENCE = re.compile(
    r"\bno\s+(?:\w+\s+){0,2}?"
    r"(?:errors?|failures?|problems?|issues?|faults?|outages?|exceptions?|timeouts?)\b",
    re.I,
)
_NORMAL_OPERATION = re.compile(
    r"\b(?:operated|operating|functioned|functioning|performed|ran|running)\s+"
    r"(?:normally|as expected|without incident)\b",
    re.I,
)
_WITHOUT_TROUBLE = re.compile(
    r"\bwithout\s+(?:any\s+)?"
    r"(?:errors?|failures?|problems?|issues?|incident|interruption)\b",
    re.I,
)
_NOTHING_WRONG = re.compile(r"\bnothing\s+(?:was\s+|is\s+)?(?:wrong|failed|amiss)\b", re.I)

_HEALTH_PATTERNS = (
    _HEALTH_STATE,
    _ABSENCE,
    _NORMAL_OPERATION,
    _WITHOUT_TROUBLE,
    _NOTHING_WRONG,
)

# A negation inside a health phrase reverses it: "is not healthy" asserts the
# opposite of "is healthy", and firing on it would be exactly backwards.
_NEGATOR = re.compile(r"\b(?:not|never|hardly|barely|n't)\b", re.I)

# Vocabulary that asserts something did go wrong.
_TROUBLE = re.compile(
    r"\b(?:error|errors|fail|failed|failing|failure|failures|timeout|timed out|"
    r"exception|crash|crashed|refused|unavailable|outage|broke|broken|down|"
    r"degraded|rejected|denied)\b",
    re.I,
)

# A claim scoped to a window cannot be settled against a single line's level:
# "no failures after 20:18" is compatible with an error at 20:17.
_TEMPORAL_SCOPE = re.compile(
    r"\b(?:after|before|since|until|between|prior to|following|once)\b", re.I
)


def asserts_no_failure(text: str) -> bool:
    """Does this claim say that nothing went wrong?

    Mixed claims — "the gateway is healthy but orders failed" — deliberately
    do not count. The health phrases are blanked out and whatever trouble
    vocabulary survives means the claim is also asserting a failure, which is
    not the shape this check is looking for.
    """
    remainder = text
    matched = False

    for pattern in _HEALTH_PATTERNS:
        for match in pattern.finditer(text):
            if _NEGATOR.search(match.group(0)):
                continue
            matched = True
            remainder = remainder.replace(match.group(0), " ")

    if not matched:
        return False
    return not _TROUBLE.search(remainder)


def contradicted_by_level(
    claims: list[tuple[str, tuple[int, ...]]],
    evidence: dict[int, Evidence],
) -> list[Unsupported]:
    """Claims of health that cite a line the log recorded as a failure.

    Only a severity actually read from the log counts. One inferred from
    message wording is a guess, and a guess must not be used to call an answer
    wrong.
    """
    found: list[Unsupported] = []

    for text, cited in claims:
        if not cited or not asserts_no_failure(text):
            continue
        if _TEMPORAL_SCOPE.search(text):
            continue

        failures = [
            evidence[i]
            for i in cited
            if i in evidence and evidence[i].has_level and evidence[i].is_failure
        ]
        if not failures:
            continue

        shown = failures[0]
        found.append(
            Unsupported(
                claim=text,
                line_ids=tuple(f.line_id for f in failures),
                kind="contradiction",
                detail=(
                    f"the claim says nothing failed, but L{shown.line_id} is an "
                    f"{shown.level} line: {shown.message or shown.text}"
                ),
            )
        )

    return found


# A count asserted about events: a bare integer followed by a counting noun,
# optionally with one adjective between them. Requiring whitespace before the
# noun keeps units out — "20%" and "5000ms" never match, and neither does the
# `12` inside a `[L12]` citation.
_COUNT_CLAIM = re.compile(
    r"\b(?P<n>\d{1,9})\s+(?:\w+\s+){0,1}"
    r"(?:times|occurrences|instances|events|entries|errors|failures|"
    r"requests|attempts|retries|exceptions|timeouts|restarts)\b",
    re.I,
)


# Numbers a tool renders as an explicit tally. Taken from the whole block, so
# the `[47x]` heading of a mined pattern supports a claim about the example
# line underneath it.
_TALLY = re.compile(
    r"\[(\d+)x\]"
    r"|\b(\d+)\s+(?:match(?:es)?|distinct|entr(?:y|ies)|occurrence|"
    r"error pattern|failure|step)"
    r"|\bcount[:=]\s*(\d+)",
    re.I,
)


def _digits_in(text: str) -> set[str]:
    """Every run of digits on the evidence line itself, citation ids excluded.

    The `12` in `[L12]` is an address, not a measurement, and must not license
    a claim of twelve failures.
    """
    without_ids = _LINE_ID.sub(" ", text)
    return set(re.findall(r"\d+", without_ids))


def _tallies_in(block: str) -> set[str]:
    """Numbers the surrounding block states as counts."""
    return {group for match in _TALLY.findall(block) for group in match if group}


def unsupported_counts(
    claims: list[tuple[str, tuple[int, ...]]],
    evidence: dict[int, Evidence],
) -> list[Unsupported]:
    """Counts asserted about events that the cited lines cannot add up to.

    A rendered log line is evidence of one event. Citing three of them
    supports "three times" and nothing larger. A number the evidence states
    for itself — the `3x` on a mined pattern, a total in a summary — supports
    whatever it says.
    """
    found: list[Unsupported] = []

    for text, cited in claims:
        known = [evidence[i] for i in cited if i in evidence]
        if not known:
            continue

        stated: set[str] = set()
        for item in known:
            stated |= _digits_in(item.text)
            stated |= _tallies_in(item.block)

        for match in _COUNT_CLAIM.finditer(text):
            raw = match.group("n")
            if raw in stated:
                continue
            if int(raw) <= len(known):
                continue

            found.append(
                Unsupported(
                    claim=text,
                    line_ids=tuple(item.line_id for item in known),
                    kind="invented-quantity",
                    detail=(
                        f"the claim counts {match.group(0).strip()}, but the "
                        f"{len(known)} cited line(s) show no such number"
                    ),
                )
            )
            break

    return found


# Generic words that name no particular service. Stripped before matching so
# "order-service" in the log and "the order service" in a claim line up.
_SERVICE_NOISE = {"service", "services", "svc", "the", "a", "an"}

# Single tokens that are ordinary English as often as they are a service name.
# Matching one of these alone would read "in order to" as the order service, so
# they only count when the claim spells the word "service" out.
_AMBIGUOUS_ALONE = {
    "order",
    "api",
    "gateway",
    "log",
    "logs",
    "event",
    "events",
    "data",
    "host",
    "node",
    "time",
    "check",
    "test",
    "search",
    "index",
    "store",
    "queue",
    "cache",
}

# The second service named is the earlier one.
_REVERSING = re.compile(
    r"\b(?:caused by|triggered by|due to|because of|downstream of|"
    r"as a (?:consequence|result) of|(?:consequence|result) of|"
    r"resulting from|resulted from|after|following|subsequent to)\b",
    re.I,
)
# The first service named is the earlier one.
_FORWARD = re.compile(
    r"\b(?:then|afterwards?|subsequently|later|followed by|caused|triggered|"
    r"led to|resulted in|cascaded (?:in)?to|propagated to|before)\b",
    re.I,
)
# A service singled out as the start of the chain.
_PRIMACY = re.compile(
    r"\b(?:first|initially|initial|originally|earliest|began|begun|started|"
    r"root cause|originated)\b",
    re.I,
)

# Only compare times of day. The rendering carries no date, so a pair far
# enough apart might straddle midnight and be in the opposite order to the one
# the clock suggests.
_MAX_ORDERING_GAP_SECONDS = 6 * 60 * 60


def _normalise(text: str) -> str:
    """Lowercase, split on punctuation, drop words that name nothing."""
    words = re.split(r"[^a-z0-9]+", text.lower())
    return " ".join(w for w in words if w and w not in _SERVICE_NOISE)


def _mention_position(claim: str, service: str) -> int | None:
    """Where a claim names this service, or None if it does not.

    A multi-token name matches on its own. A single token that doubles as
    ordinary English has to be followed by the word "service" to count.
    """
    normalised_claim = _normalise(claim)
    name = _normalise(service)
    if not name:
        return None

    pattern = re.compile(rf"\b{re.escape(name)}\b")
    match = pattern.search(normalised_claim)
    if not match:
        return None

    if " " not in name and name in _AMBIGUOUS_ALONE:
        # `_normalise` has already removed the word, so look at the raw claim.
        spelled_out = re.search(rf"\b{re.escape(name)}[\s\-_]+(?:service|svc)\b", claim, re.I)
        if not spelled_out:
            return None

    return match.start()


def _first_failure_times(evidence: dict[int, Evidence]) -> dict[str, time]:
    """When each service was first seen failing, across all the evidence."""
    earliest: dict[str, time] = {}
    for item in evidence.values():
        if not (item.service and item.stamp and item.has_level and item.is_failure):
            continue
        current = earliest.get(item.service)
        if current is None or item.stamp < current:
            earliest[item.service] = item.stamp
    return earliest


def _seconds(value: time) -> int:
    return value.hour * 3600 + value.minute * 60 + value.second


def _claimed_order(claim: str, first: str, second: str) -> tuple[str, str] | None:
    """Which service does the claim put earlier?

    `first` and `second` are the two services in the order they are named.
    Returns (earlier, later), or None when the claim asserts no ordering.
    """
    start = _mention_position(claim, first)
    end = _mention_position(claim, second)
    if start is None or end is None:
        return None

    normalised = _normalise(claim)
    between = normalised[start:end]

    # "caused by" contains "caused", so the reversing sense is tested first.
    if _REVERSING.search(between):
        return second, first
    if _FORWARD.search(between):
        return first, second

    # Neither connective: fall back to a service singled out as the start.
    if _PRIMACY.search(between):
        return first, second
    if _PRIMACY.search(normalised[end:]):
        return second, first

    return None


def inverted_ordering(
    claims: list[tuple[str, tuple[int, ...]]],
    evidence: dict[int, Evidence],
) -> list[Unsupported]:
    """Claims that put one service's failure before another's, backwards.

    This is the failure that prompted the whole module: on real AKS data an
    answer inverted a causal chain while every citation resolved cleanly. The
    ordering is checked against every line the tools returned, not only the
    cited ones, because that is what the model was shown.

    Only failures with a timestamp read from the log take part, and only two
    named services at a time — a claim naming three is past the point where a
    string can settle what it meant.
    """
    found: list[Unsupported] = []
    earliest = _first_failure_times(evidence)
    if len(earliest) < 2:
        return found

    for text, cited in claims:
        if not cited or not _TROUBLE.search(text):
            continue

        named = sorted(
            (position, service)
            for service in earliest
            if (position := _mention_position(text, service)) is not None
        )
        if len(named) != 2:
            continue

        (_, first), (_, second) = named
        order = _claimed_order(text, first, second)
        if order is None:
            continue

        claimed_earlier, claimed_later = order
        actual_earlier = earliest[claimed_earlier]
        actual_later = earliest[claimed_later]
        if abs(_seconds(actual_earlier) - _seconds(actual_later)) > _MAX_ORDERING_GAP_SECONDS:
            continue
        if actual_earlier <= actual_later:
            continue

        found.append(
            Unsupported(
                claim=text,
                line_ids=cited,
                kind="inverted-ordering",
                detail=(
                    f"the claim puts {claimed_earlier} before {claimed_later}, but "
                    f"the log shows {claimed_later} failing first at "
                    f"{actual_later.strftime('%H:%M:%S')} and {claimed_earlier} at "
                    f"{actual_earlier.strftime('%H:%M:%S')}"
                ),
            )
        )

    return found
