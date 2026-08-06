"""Template mining.

The regex grouping it replaced could only collapse variable shapes that had
been anticipated. On 1,379 OpenSSH failures it produced 185 groups, splitting
one brute-force attack across a group per username; Drain produces 13.
"""

import pytest

from loglens.analysis import top_errors
from loglens.drain import WILDCARD, DrainTree, mine, preprocess, similarity
from loglens.models import LogEntry


def entry(message: str, service: str = "svc") -> LogEntry:
    return LogEntry(line_no=1, raw=message, level="ERROR", service=service, message=message)


class TestLearnsVariablePositions:
    def test_a_varying_token_becomes_a_wildcard(self):
        templates = mine(
            [
                "Connection timeout after 5000ms to db-01",
                "Connection timeout after 3000ms to db-04",
                "Connection timeout after 12000ms to db-17",
            ]
        )
        assert len(templates) == 1
        assert templates[0].count == 3
        assert WILDCARD in templates[0].text

    def test_it_learns_a_variable_no_regex_would_have_caught(self):
        """Usernames carry no digits and no punctuation to key off. The regex
        approach could not have been written to collapse these."""
        templates = mine(
            [
                f"Failed password for {user} from 10.0.0.1 port 22 ssh2"
                for user in ("root", "admin", "deploy", "jenkins", "postgres")
            ]
        )
        assert len(templates) == 1
        assert templates[0].count == 5
        assert templates[0].text.startswith("Failed password for <*>")

    def test_constant_tokens_survive(self):
        template = mine(["Disk full on /var", "Disk full on /tmp"])[0]
        assert template.text.startswith("Disk full on")

    def test_genuinely_different_messages_stay_apart(self):
        templates = mine(["Disk full on /var", "Network unreachable"])
        assert len(templates) == 2

    def test_different_token_counts_never_merge(self):
        templates = mine(["a b c", "a b c d e"])
        assert len(templates) == 2


class TestSemanticNumbersAreNotWildcarded:
    """Regression carried over from the regex implementation: a 503 is an
    upstream outage and a 404 is a bad route. Merging them reports two
    incidents as one."""

    @pytest.mark.parametrize(
        "left,right",
        [
            ("Gateway returned HTTP 503", "Gateway returned HTTP 404"),
            ("Pod exited with exit_code 137", "Pod exited with exit_code 1"),
            ("Upstream status 500", "Upstream status 429"),
        ],
    )
    def test_codes_separate_templates(self, left, right):
        assert len(mine([left, right])) == 2

    def test_the_same_code_still_groups(self):
        templates = mine(["Gateway returned HTTP 503"] * 3)
        assert len(templates) == 1
        assert templates[0].count == 3


class TestPreprocessing:
    @pytest.mark.parametrize(
        "message,placeholder",
        [
            ("connect to 10.0.0.1 failed", "<IP>"),
            ("connect to 10.0.0.1:5432 failed", "<IP>"),
            ("request 550e8400-e29b-41d4-a716-446655440000 failed", "<UUID>"),
            ("fault at 0xdeadbeef", "<HEX>"),
            ("trace a1b2c3d4e5f6a7b8 failed", "<ID>"),
        ],
    )
    def test_occurrence_identifiers_are_masked(self, message, placeholder):
        assert placeholder in preprocess(message)

    def test_ordinary_words_are_left_alone(self):
        text = "Failed to publish event to Kafka topic orders"
        assert preprocess(text) == text


class TestSimilarity:
    def test_identical_is_one(self):
        assert similarity(["a", "b"], ["a", "b"]) == 1.0

    def test_disjoint_is_zero(self):
        assert similarity(["a", "b"], ["c", "d"]) == 0.0

    def test_half(self):
        assert similarity(["a", "b"], ["a", "d"]) == 0.5

    def test_a_wildcard_position_counts_as_disagreement(self):
        """Otherwise a heavily generalised template absorbs everything it is
        compared against, and grouping collapses to one bucket."""
        assert similarity([WILDCARD, "b"], ["a", "b"]) == 0.5


class TestBounds:
    def test_template_growth_is_capped(self):
        tree = DrainTree(max_templates=5)
        for i in range(200):
            tree.add(f"distinct message number {i} alpha beta gamma delta")
        assert len(tree.templates()) <= 5

    def test_children_per_leaf_are_capped(self):
        tree = DrainTree(max_children=3)
        for i in range(50):
            tree.add(f"same prefix here {i} {i * 2} {i * 3}")
        for group in tree._leaves.values():
            assert len(group) <= 3

    def test_every_message_is_counted_even_at_capacity(self):
        tree = DrainTree(max_templates=2)
        for i in range(30):
            tree.add(f"unique alpha beta {i} gamma")
        assert sum(t.count for t in tree.templates()) == 30

    def test_an_empty_message_does_not_crash(self):
        assert mine(["", "   "])


class TestOrdering:
    def test_most_frequent_first(self):
        messages = ["common failure here"] * 5 + ["rare thing over there"]
        templates = mine(messages)
        assert templates[0].count == 5

    def test_examples_are_kept_but_bounded(self):
        template = mine([f"failure number {i} occurred" for i in range(20)])[0]
        assert template.examples
        assert len(template.examples) <= 3


class TestTopErrorsUsesTemplates:
    def test_usernames_collapse_into_one_group(self):
        entries = [
            entry(f"Failed password for {user} from 10.0.0.1 port 22 ssh2")
            for user in ("root", "admin", "deploy", "jenkins")
        ]
        groups = top_errors(entries)
        assert len(groups) == 1
        assert groups[0].count == 4

    def test_status_codes_still_split(self):
        entries = [
            entry("Gateway returned HTTP 503"),
            entry("Gateway returned HTTP 404"),
        ]
        assert len(top_errors(entries)) == 2

    def test_non_failures_are_ignored(self):
        clean = LogEntry(line_no=1, raw="x", level="INFO", message="all good")
        assert top_errors([clean]) == []

    def test_services_and_timestamps_are_still_collected(self):
        entries = [
            entry("Connection refused by upstream", service="a"),
            entry("Connection refused by upstream", service="b"),
        ]
        group = top_errors(entries)[0]
        assert group.services == ["a", "b"]
        assert group.count == 2
