"""Log template mining, following the Drain algorithm.

The previous grouping applied a fixed list of regexes — replace anything that
looks like an id, a hostname or a number, then group by what is left. That
works only for the variable shapes somebody thought of in advance. It cannot
learn that the third token of a particular message is a username, and it
over-collapses whenever a real word happens to contain a digit.

Drain (He et al., ICWS 2017) learns templates instead. Messages are routed
through a fixed-depth tree — first by token count, then by leading tokens —
and within each leaf compared token by token against existing templates. A
message close enough to a template joins it, and any position where the two
disagree becomes a wildcard. Positions that vary are discovered from the data
rather than declared up front.

Two departures from the paper, both deliberate:

Preprocessing still masks ids, addresses and UUIDs, because those vary per
occurrence and would otherwise put every message in its own group before the
tree can generalise. This is the "domain knowledge" step the paper allows for.

Status and exit codes are held out of the wildcarding and made part of the
tree path. Drain would treat 503 and 404 as one variable position, merging an
outage with a bad route. They are different failures, and a grouping that
hides that is worse than one that splits too finely.
"""

import re
from dataclasses import dataclass, field

WILDCARD = "<*>"

# Applied before tokenisation. Only shapes that are variable by construction —
# anything that identifies one occurrence of an event rather than describing
# the event — belong here.
_PREPROCESS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<ID>"),
)

# Numbers whose value distinguishes one failure from another. A 503 is an
# upstream outage, a 404 is a bad route, an exit code 137 is an OOM kill.
_SEMANTIC_NUMBER = re.compile(
    r"\b(?:http|https|status(?:[ _-]?code)?|code|response|exit(?:[ _-]?code)?|"
    r"signal|errno)\b\W{0,3}(\d{1,4})\b",
    re.I,
)

_HAS_DIGIT = re.compile(r"\d")


@dataclass
class Template:
    """One learned template and the messages that matched it."""

    tokens: list[str]
    count: int = 0
    examples: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.tokens)

    @property
    def parameter_count(self) -> int:
        return sum(1 for token in self.tokens if token == WILDCARD)


def preprocess(message: str) -> str:
    """Mask the shapes that identify an occurrence rather than an event."""
    for pattern, placeholder in _PREPROCESS:
        message = pattern.sub(placeholder, message)
    return message


def semantic_numbers(message: str) -> tuple[str, ...]:
    """Status and exit codes, which separate failures rather than label one."""
    return tuple(sorted(_SEMANTIC_NUMBER.findall(message)))


def _mask_token(token: str) -> str:
    """Tree routing ignores tokens that carry a digit, as the paper specifies."""
    return WILDCARD if _HAS_DIGIT.search(token) else token


def similarity(template: list[str], tokens: list[str]) -> float:
    """Share of positions where the template and the message agree.

    Wildcard positions count as disagreement, so a template that has already
    generalised heavily does not absorb everything it is compared against.
    """
    if not template:
        return 0.0
    matches = sum(1 for a, b in zip(template, tokens, strict=True) if a == b)
    return matches / len(template)


class DrainTree:
    """Fixed-depth prefix tree over log messages.

    depth is the number of leading tokens used for routing. Deeper separates
    more aggressively and costs more groups; the paper's default of two token
    layers holds up well and is what is used here.
    """

    def __init__(
        self,
        depth: int = 2,
        similarity_threshold: float = 0.5,
        max_children: int = 100,
        max_templates: int = 5_000,
    ):
        self.depth = max(depth, 1)
        self.similarity_threshold = similarity_threshold
        self.max_children = max_children
        self.max_templates = max_templates
        # Leaf key -> templates found under it.
        self._leaves: dict[tuple, list[Template]] = {}
        self._template_count = 0

    def _leaf_key(self, tokens: list[str], codes: tuple[str, ...]) -> tuple:
        """Route by length, leading tokens, and any status codes present.

        The codes are part of the path rather than the comparison, so two
        messages differing only in their status code cannot reach the same
        template at all.
        """
        prefix = tuple(_mask_token(t) for t in tokens[: self.depth])
        return (len(tokens), prefix, codes)

    def add(self, message: str) -> Template:
        """File a message under a template, creating one if nothing fits."""
        codes = semantic_numbers(message)
        tokens = preprocess(message).split()
        if not tokens:
            tokens = [""]

        key = self._leaf_key(tokens, codes)
        candidates = self._leaves.setdefault(key, [])

        best: Template | None = None
        best_score = -1.0
        for template in candidates:
            score = similarity(template.tokens, tokens)
            if score > best_score:
                best, best_score = template, score

        if best is not None and best_score >= self.similarity_threshold:
            # Any position where the two disagree is a parameter, not content.
            best.tokens = [
                a if a == b else WILDCARD for a, b in zip(best.tokens, tokens, strict=True)
            ]
            best.count += 1
            if len(best.examples) < 3:
                best.examples.append(message)
            return best

        # Refusing to grow without bound is what keeps a pathological log from
        # turning every line into its own template.
        at_capacity = (
            len(candidates) >= self.max_children or self._template_count >= self.max_templates
        )
        if at_capacity and candidates:
            fallback = candidates[0]
            fallback.count += 1
            return fallback

        template = Template(tokens=list(tokens), count=1, examples=[message])
        candidates.append(template)
        self._template_count += 1
        return template

    def templates(self) -> list[Template]:
        """Every template found, most frequent first."""
        found = [t for group in self._leaves.values() for t in group]
        found.sort(key=lambda t: (-t.count, t.text))
        return found


def mine(messages: list[str], **kwargs) -> list[Template]:
    """Convenience wrapper: build a tree over messages and return templates."""
    tree = DrainTree(**kwargs)
    for message in messages:
        tree.add(message)
    return tree.templates()
