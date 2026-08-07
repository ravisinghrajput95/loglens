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
    mentions: dict[int, str] = {}

    for source in sources:
        for line in source.splitlines():
            ids = [int(m) for m in _LINE_ID.findall(line)]
            if not ids:
                continue

            parsed = _parse_line(line)
            if parsed is not None:
                # A structured rendering wins over a passing mention, and the
                # first one wins over a later repeat: tools list a line in full
                # before summarising it.
                evidence.setdefault(parsed.line_id, parsed)
                ids = [i for i in ids if i != parsed.line_id]

            for line_id in ids:
                mentions.setdefault(line_id, line.strip())

    for line_id, text in mentions.items():
        if line_id not in evidence:
            evidence[line_id] = Evidence(line_id=line_id, text=text)

    return evidence
