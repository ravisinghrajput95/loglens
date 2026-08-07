"""Checking an answer against the evidence the tools actually returned.

The first version of this compared quoted passages against tool output as
plain text. Two problems emerged from a design review, and both are structural
rather than fixable by tuning:

1. It verified provenance, not truth. A passage that appeared in tool output
   was marked supported — including a line an attacker had written into the
   log. That made the check an amplifier for injected content rather than a
   defence against it.
2. It only saw text the model chose to put in quotes. Dropping the quotation
   marks made any fabrication invisible, so the check policed a formatting
   habit rather than honesty.

This version works on citations instead. Tools render each log line with an id
like `[L42]`; the model is asked to cite the ids a finding rests on. That
converts verification into a referential-integrity problem with three separate
questions, each answerable deterministically:

  - Does every cited id exist in what the tools returned?  (fabricated source)
  - Does every substantive claim carry a citation?          (uncited assertion)
  - Do any cited lines come from flagged, hostile content?  (poisoned evidence)

A fourth question — does the cited line actually support the claim? — was for
a long time answered only by saying it could not be. `support.py` now answers
part of it: the mechanical contradictions, where the claim and the line it
cites disagree about severity, about a count, or about which of two services
failed first. That is not entailment, and it is not sold as entailment. It
catches specific wrong answers and stays quiet on everything else, including
plenty of wrong answers it has no way to see.
"""

import re
from dataclasses import dataclass, field

from .support import (
    Unsupported,
    contradicted_by_level,
    index_evidence,
    unsupported_counts,
)

# The citation form tools emit and the model is asked to reuse.
CITATION = re.compile(r"\[L(\d+)\]")

# Sentence-ish units. Splitting on terminators and list markers keeps bullet
# points, which carry most findings, as separate claims.
_CLAIM_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
# Bullets and numbered markers only. An earlier version also stripped a bare
# "**", which chewed the opening of a bold heading — "**Why**" was reported
# back to the user as "*Why**".
_LIST_MARKER = re.compile(r"^\s*(?:[-*+•]\s+|\d+[.)]\s+)")

# A claim short enough to be a heading or a fragment carries no assertion worth
# checking. "**Summary**" and "Recommendations" should not be demanded to cite.
MIN_CLAIM_LENGTH = 40

# Claims that assert something about the log. Recommendations and questions do
# not rest on evidence in the same way, so requiring citations from them would
# generate noise that trains people to ignore the warning.
_EVIDENTIAL = re.compile(
    r"\b(?:error|errors|fail|failed|failure|failures|timeout|timed out|exception|"
    r"crash|crashed|refused|unavailable|down|spike|latency|slow|restart|"
    r"occurred|reported|shows?|indicates?|observed|detected|logged|"
    r"service|entries|entry|rate|count)\b",
    re.I,
)
_ADVISORY = re.compile(
    r"^\s*(?:consider|recommend|you should|investigate|check|verify|review|"
    r"ensure|implement|increase|reduce|monitor|add|configure|next step)",
    re.I,
)


@dataclass
class Claim:
    text: str
    citations: tuple[int, ...]

    @property
    def cited(self) -> bool:
        return bool(self.citations)


@dataclass
class Report:
    claims: list[Claim] = field(default_factory=list)
    unknown_citations: list[int] = field(default_factory=list)
    uncited: list[Claim] = field(default_factory=list)
    poisoned: list[int] = field(default_factory=list)
    available: int = 0
    # Claims whose own citation contradicts them. See `support.py` — these are
    # narrow, deterministic checks, not entailment.
    unsupported: list[Unsupported] = field(default_factory=list)

    @property
    def cited_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.cited]

    @property
    def coverage(self) -> float:
        """Share of evidential claims that carry a citation."""
        if not self.claims:
            return 1.0
        return len(self.cited_claims) / len(self.claims)

    @property
    def clean(self) -> bool:
        return not (self.unknown_citations or self.poisoned or self.unsupported)


def available_ids(sources: list[str]) -> set[int]:
    """Every line id the tools actually showed."""
    ids: set[int] = set()
    for source in sources:
        ids.update(int(match) for match in CITATION.findall(source))
    return ids


def suspicious_ids(sources: list[str]) -> set[int]:
    """Line ids the parser flagged as probable injection attempts.

    Read back out of the rendered tool output rather than passed alongside it,
    so the check works on exactly the text the model was given.
    """
    flagged: set[int] = set()
    for source in sources:
        for line in source.splitlines():
            if "SUSPICIOUS" in line:
                flagged.update(int(match) for match in CITATION.findall(line))
    return flagged


def split_claims(answer: str) -> list[str]:
    """Break an answer into units that can each be checked for a citation."""
    units: list[str] = []
    for raw in _CLAIM_SPLIT.split(answer):
        text = _LIST_MARKER.sub("", raw).strip()
        if len(text) < MIN_CLAIM_LENGTH:
            continue
        units.append(text)
    return units


def is_evidential(text: str) -> bool:
    """Does this claim assert something the log should back up?"""
    if _ADVISORY.match(text):
        return False
    return bool(_EVIDENTIAL.search(text))


def verify(
    answer: str,
    sources: list[str],
    suspicious_ids: set[int] | None = None,
) -> Report:
    """Check an answer's citations against the evidence the tools returned."""
    report = Report()
    if not answer or not sources:
        return report

    known = available_ids(sources)
    report.available = len(known)
    flagged = suspicious_ids or set()

    # Citations are checked across the whole answer, not per claim. Claim
    # splitting drops fragments too short to assert anything, and a fabricated
    # id inside one of those would otherwise never be looked at.
    seen: set[int] = set()
    for match in CITATION.findall(answer):
        line_id = int(match)
        if line_id in seen:
            continue
        seen.add(line_id)
        if line_id not in known:
            report.unknown_citations.append(line_id)
        if line_id in flagged:
            report.poisoned.append(line_id)

    # Coverage is a separate question, and only meaningful for claims that
    # assert something about the log.
    units = split_claims(answer)
    for text in units:
        if not is_evidential(text):
            continue
        claim = Claim(text=text, citations=tuple(int(m) for m in CITATION.findall(text)))
        report.claims.append(claim)
        if not claim.cited:
            report.uncited.append(claim)

    # Does the cited line actually support the claim? Only ever a partial
    # answer — see `support.py` for why it is deliberately narrow. Run over
    # every unit rather than only the evidential ones, since each check gates
    # itself on the shape of claim it can speak to.
    pairs = [(text, tuple(int(m) for m in CITATION.findall(text))) for text in units]
    evidence = index_evidence(sources)
    report.unsupported = contradicted_by_level(pairs, evidence) + unsupported_counts(
        pairs, evidence
    )

    return report


def format_report(report: Report, strict: bool = False) -> str:
    """A warning for the user, or empty when there is nothing worth saying."""
    lines: list[str] = []

    if report.unknown_citations:
        ids = ", ".join(f"L{i}" for i in sorted(report.unknown_citations))
        many = len(report.unknown_citations) > 1
        lines.append(
            f"FABRICATED CITATION{'S' if many else ''}: the answer cites {ids}, "
            f"which the tools never returned. "
            f"{'Those claims rest' if many else 'That claim rests'} on nothing."
        )

    if report.poisoned:
        ids = ", ".join(f"L{i}" for i in sorted(report.poisoned))
        many = len(report.poisoned) > 1
        lines.append(
            f"POISONED EVIDENCE: {ids} {'were' if many else 'was'} flagged as a "
            "probable prompt-injection attempt. A claim resting on "
            f"{'them' if many else 'it'} repeats what an attacker wrote, not what "
            "the system did."
        )

    if report.unsupported:
        many = len(report.unsupported) > 1
        lines.append(
            f"UNSUPPORTED BY THE CITED LINE: "
            f"{len(report.unsupported)} claim{'s' if many else ''} "
            f"{'contradict' if many else 'contradicts'} the evidence "
            f"{'they cite' if many else 'it cites'}."
        )
        for issue in report.unsupported[:5]:
            text = issue.claim if len(issue.claim) <= 90 else issue.claim[:87] + "..."
            lines.append(f"  - {text}")
            lines.append(f"      {issue.detail}")
        if len(report.unsupported) > 5:
            lines.append(f"  ... and {len(report.unsupported) - 5} more")

    if report.claims:
        pct = report.coverage * 100
        if report.uncited and (strict or pct < 100):
            lines.append(
                f"Citation coverage {pct:.0f}% "
                f"({len(report.cited_claims)} of {len(report.claims)} factual "
                "claims cite a line). Uncited:"
            )
            for claim in report.uncited[:5]:
                text = claim.text if len(claim.text) <= 110 else claim.text[:107] + "..."
                lines.append(f"  - {text}")
            if len(report.uncited) > 5:
                lines.append(f"  ... and {len(report.uncited) - 5} more")

    if not lines:
        return ""

    lines.append(
        "Verification checks that cited lines exist, are not hostile, and do "
        "not contradict the claim on level, count or ordering. It cannot tell "
        "in general whether a line supports the claim made about it."
    )
    return "\n".join(lines)
