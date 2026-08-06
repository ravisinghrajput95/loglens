"""Removing credentials and personal data before log text reaches the model.

Applied at parse time rather than at render time, deliberately: a secret that
is never held in memory cannot be leaked by a later feature, a crash dump, or
a tool that forgets to redact. The cost is that you cannot search for a secret
by value, which is an acceptable trade.

Every rule is compiled into one alternation and applied in a single pass.
Running fourteen separate patterns over every line of a large file tripled
parse time; scanning once does not.

This is a mitigation, not a guarantee. Secret formats change, and a detector
built from patterns will always trail them.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache

# Order matters: alternation is tried left to right at each position, so
# structured credentials must precede the looser key/value rule that would
# otherwise mangle them.
#
# The third element is a literal the rule cannot match without. Several of
# these patterns open with an unbounded character class before their anchor —
# DSN_CREDENTIALS is [a-zA-Z][a-zA-Z0-9+.-]*:// — and on a long run of
# characters the class accepts, the engine consumes to the end, fails to find
# the anchor, and retries from the next position. That is quadratic: a single
# 20 KB line took 1.4 seconds in DSN_CREDENTIALS alone, and a 200 KB line took
# over two minutes across the rule set. Checking for the literal first is one
# linear scan and removes the whole class of problem.
_RULES: tuple[tuple[str, str, str | None], ...] = (
    (
        "PRIVATE_KEY",
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----",
        "-----begin",
    ),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}", "eyj"),
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b", None),
    ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{16,}\b", "gh"),
    ("SLACK_TOKEN", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "xox"),
    ("STRIPE_KEY", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b", "k_"),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b", "aiza"),
    # Credentials inside a connection string. The host and user stay: they are
    # diagnostic, and only the password is a secret.
    (
        "DSN_CREDENTIALS",
        r"(?P<dsn_head>[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:@/]+:)(?P<dsn_pass>[^\s@/]+)@",
        "://",
    ),
    ("AUTH_HEADER", r"\b(?:Authorization|Proxy-Authorization)\s*[:=]\s*\S+", "auth"),
    ("BEARER_TOKEN", r"\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{12,}", None),
    (
        "SECRET_ASSIGNMENT",
        r"(?P<sa_head>\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
        r"client[_-]?secret|auth|credential)s?\b\"?\s*[:=]\s*\"?)"
        r"(?P<sa_value>[^\s,;\"'}\]]{3,})",
        None,
    ),
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "@"),
    # Must end on a digit: a trailing separator inside the repetition would
    # swallow the space after the number and run into the following word.
    ("CARD_NUMBER", r"\b\d(?:[ -]?\d){12,18}\b", None),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", None),
)


@lru_cache(maxsize=64)
def _build(kinds: tuple[str, ...]) -> re.Pattern | None:
    """Compile the alternation for exactly these rules. Cached by rule set."""
    chosen = [(k, p) for k, p, _ in _RULES if k in kinds]
    if not chosen:
        return None
    return re.compile(
        "|".join(f"(?P<{kind}>{pattern})" for kind, pattern in chosen), re.IGNORECASE
    )


def _applicable(text: str) -> re.Pattern | None:
    """Only the rules whose required literal is present in the text."""
    lowered = text.lower()
    kinds = tuple(
        kind for kind, _, required in _RULES if required is None or required in lowered
    )
    return _build(kinds)


_CARD_LOOKS_LIKE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _luhn(digits: str) -> bool:
    """Card-number checksum, so long ids are not mistaken for card numbers."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact(text: str) -> RedactionResult:
    """Replace credentials and personal data with typed placeholders."""
    if not text:
        return RedactionResult(text)

    counts: dict[str, int] = {}

    def replace(match: re.Match) -> str:
        kind = match.lastgroup
        # Inner named groups report themselves as lastgroup; map them back.
        if kind in ("dsn_head", "dsn_pass"):
            kind = "DSN_CREDENTIALS"
        elif kind in ("sa_head", "sa_value"):
            kind = "SECRET_ASSIGNMENT"

        if kind == "DSN_CREDENTIALS":
            counts["DSN_CREDENTIALS"] = counts.get("DSN_CREDENTIALS", 0) + 1
            return f"{match.group('dsn_head')}<REDACTED:PASSWORD>@"

        if kind == "SECRET_ASSIGNMENT":
            counts["SECRET_ASSIGNMENT"] = counts.get("SECRET_ASSIGNMENT", 0) + 1
            return f"{match.group('sa_head')}<REDACTED:SECRET>"

        if kind == "CARD_NUMBER":
            raw = match.group(0)
            if _CARD_LOOKS_LIKE_DATE.match(raw):
                return raw
            digits = re.sub(r"\D", "", raw)
            if not (13 <= len(digits) <= 19) or not _luhn(digits):
                return raw
            counts["CARD_NUMBER"] = counts.get("CARD_NUMBER", 0) + 1
            return "<REDACTED:CARD_NUMBER>"

        counts[kind] = counts.get(kind, 0) + 1
        return f"<REDACTED:{kind}>"

    pattern = _applicable(text)
    if pattern is None:
        return RedactionResult(text)
    return RedactionResult(pattern.sub(replace, text), counts)


def summarize_counts(counts: dict[str, int]) -> str:
    """One line describing what was removed, for the user and the model."""
    if not counts:
        return ""
    parts = ", ".join(f"{kind.lower()} x{n}" for kind, n in sorted(counts.items()))
    return f"Redacted before analysis: {parts}."
