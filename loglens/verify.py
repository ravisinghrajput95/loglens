"""Checking that an answer only quotes what the tools actually returned.

The tools cannot fabricate: they compute from the file. The model can, and was
observed doing exactly that — quoting eight log lines it had never retrieved,
formatted as logback when the file was JSON. A system prompt cannot prevent
this. Comparing the finished answer against the tool output can.

This runs after the agent is done and needs no cooperation from the model.
"""

import re
from dataclasses import dataclass, field

# Spans the model presents as verbatim: markdown code spans and double-quoted
# text. Both patterns match a delimiter pair with no delimiter inside, so a
# sentence containing two separate code spans yields two quotes rather than
# one quote made of the prose between them.
_CODE_SPAN = re.compile(r"`([^`\n]+)`")
_DOUBLE_QUOTED = re.compile(r"\"([^\"\n]+)\"")

# Below this length a span carries no real claim — "ERROR", "db", "20%" — and
# checking it produces noise rather than signal.
MIN_QUOTE_LENGTH = 10


def normalize(text: str) -> str:
    """Fold the differences that don't change what is being claimed."""
    text = re.sub(r"\s+", " ", text)
    return text.strip().strip(".,;:").casefold()


def extract_quotes(answer: str) -> list[str]:
    """Pull the spans an answer presents as quoted evidence."""
    seen: dict[str, str] = {}
    for pattern in (_CODE_SPAN, _DOUBLE_QUOTED):
        for raw in pattern.findall(answer):
            candidate = raw.strip()
            if len(candidate) < MIN_QUOTE_LENGTH:
                continue
            key = normalize(candidate)
            if key and key not in seen:
                seen[key] = candidate
    return list(seen.values())


@dataclass
class Report:
    checked: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    @property
    def supported(self) -> int:
        return len(self.checked) - len(self.unsupported)

    @property
    def clean(self) -> bool:
        return not self.unsupported


def verify(answer: str, sources: list[str], allow: list[str] | None = None) -> Report:
    """Check every quoted span in `answer` against the text the tools returned.

    `allow` covers spans that are legitimately not log content — tool names the
    model refers to by name, for instance.
    """
    corpus = normalize(" ".join(sources))
    permitted = {normalize(a) for a in (allow or [])}

    report = Report()
    for quote in extract_quotes(answer):
        report.checked.append(quote)
        key = normalize(quote)
        if key in permitted or key in corpus:
            continue
        report.unsupported.append(quote)
    return report


def format_report(report: Report) -> str:
    """A warning to show the user, or empty when there is nothing to say."""
    if report.clean:
        return ""

    lines = [
        f"Warning: {len(report.unsupported)} of {len(report.checked)} quoted "
        "passages do not appear in the tool output. The model may have "
        "invented them:",
    ]
    for quote in report.unsupported[:10]:
        shown = quote if len(quote) <= 100 else quote[:97] + "..."
        lines.append(f"  - {shown}")
    if len(report.unsupported) > 10:
        lines.append(f"  ... and {len(report.unsupported) - 10} more")
    lines.append("Treat those as unverified. A stronger model usually fixes this.")
    return "\n".join(lines)
