"""Reading tool output back into the evidence behind each citation.

The support checks are only as good as what they think the cited line said, so
these tests pin the parsing against the renderings this codebase actually
emits — `LogEntry.cite()` and the trace steps in `report.py` — rather than
against a shape invented here.
"""

import json
from datetime import datetime, time

from loglens.models import LogEntry
from loglens.support import (
    asserts_no_failure,
    contradicted_by_level,
    index_evidence,
    unsupported_counts,
)
from loglens.tools import top_errors

RENDERED = [
    "3 match(es):\n"
    "[L12] 20:17:00 ERROR order-service          Failed to publish to Kafka topic orders-v1\n"
    "[L13] 20:17:05 WARN  order-service          Circuit breaker switched to OPEN\n"
    "[L14] 20:17:08 ERROR notification-service   SMTP connection refused\n"
]


def test_indexes_every_rendered_line():
    evidence = index_evidence(RENDERED)
    assert set(evidence) == {12, 13, 14}


def test_reads_level_service_and_message():
    got = index_evidence(RENDERED)[12]
    assert got.level == "ERROR"
    assert got.service == "order-service"
    assert got.message == "Failed to publish to Kafka topic orders-v1"
    assert got.stamp == time(20, 17, 0)
    assert got.is_failure


def test_non_failure_level_is_not_a_failure():
    assert not index_evidence(RENDERED)[13].is_failure


def test_text_keeps_the_whole_line_minus_the_id():
    got = index_evidence(RENDERED)[14]
    assert got.text.startswith("20:17:08 ERROR")
    assert "SMTP connection refused" in got.text
    assert "[L14]" not in got.text


def test_parses_what_cite_actually_renders():
    """The index must track the renderer, not a guess at it."""
    entry = LogEntry(
        line_no=42,
        raw="",
        level="ERROR",
        service="payments",
        message="Upstream returned 502",
        timestamp=datetime(2026, 7, 30, 20, 15, 31),
    )

    got = index_evidence([entry.cite()])[42]
    assert got.level == "ERROR"
    assert got.service == "payments"
    assert got.message == "Upstream returned 502"
    assert got.stamp == time(20, 15, 31)


def test_trace_step_rendering_without_a_clock():
    """report.py renders trace steps with a gap where the timestamp goes."""
    step = "   +   5847ms [L13] WARN  order-service        Circuit breaker OPEN"
    got = index_evidence([step])[13]
    assert got.level == "WARN"
    assert got.service == "order-service"
    assert got.message == "Circuit breaker OPEN"
    assert got.stamp is None


def test_missing_timestamp_renders_and_parses_as_absent():
    line = "[L7] --:--:-- ERROR db   Connection refused"
    got = index_evidence([line])[7]
    assert got.stamp is None
    assert got.level == "ERROR"


def test_inferred_level_is_not_treated_as_read():
    """`--infer-severity` marks a guessed level with `~`.

    A claim about failure cannot be settled against a level nobody logged.
    """
    line = "[L9] 07:13:43 ERROR~sshd                  Failed password for root"
    got = index_evidence([line])[9]
    assert got.level == "ERROR"
    assert got.level_inferred
    assert not got.has_level


def test_read_level_counts_as_read():
    assert index_evidence(RENDERED)[12].has_level


def test_line_with_no_level_column_keeps_its_message():
    """Syslog and friends carry no severity at all."""
    line = "[L5] 11:04:43       sshd                   Accepted publickey for ravi"
    got = index_evidence([line])[5]
    assert got.level == ""
    assert not got.has_level
    assert "Accepted publickey" in got.message


def test_passing_mention_is_kept_as_evidence():
    """`first at [L12]` inside a pattern summary is still something."""
    summary = (
        "  [3x] Failed to publish event to Kafka topic <NAME>\n"
        "        order-service  20:17:00-20:17:00  first at [L12]\n"
    )
    got = index_evidence([summary])[12]
    assert "Failed to publish" not in got.text or "first at" in got.text
    assert got.line_id == 12


def test_full_rendering_beats_a_passing_mention():
    """A line listed in full and then summarised keeps the full version."""
    sources = RENDERED + [
        "  [1x] Kafka publish failed\n        order-service  first at [L12]\n"
    ]
    got = index_evidence(sources)[12]
    assert got.service == "order-service"
    assert got.message == "Failed to publish to Kafka topic orders-v1"


def test_mention_only_id_has_no_invented_level():
    """Absence of evidence must not be rendered as evidence of health."""
    got = index_evidence(["  [1x] something\n        svc  first at [L88]\n"])[88]
    assert got.level == ""
    assert not got.has_level
    assert not got.is_failure


def test_uncited_source_text_yields_nothing():
    assert index_evidence(["no citations here at all"]) == {}


def test_empty_sources():
    assert index_evidence([]) == {}


def test_lone_token_after_the_level_is_a_message_not_a_service():
    """A one-word message must not be promoted into the service column.

    Later checks compare services by name, so inventing one from the only
    token on the line would attribute a claim to a service nobody logged.
    """
    got = index_evidence(["[L5] 11:04:43 ERROR   restarting"])[5]
    assert got.service == ""
    assert got.message == "restarting"


# ---------------------------------------------------------------------------
# Contradiction: the claim says nothing failed, the cited line is a failure
# ---------------------------------------------------------------------------


def test_health_claim_citing_an_error_line_is_flagged():
    """The blind spot this check exists to close."""
    issues = contradicted_by_level(
        [("The order service is healthy and no failures were observed", (12,))],
        index_evidence(RENDERED),
    )
    assert len(issues) == 1
    assert issues[0].kind == "contradiction"
    assert issues[0].line_ids == (12,)
    assert "ERROR" in issues[0].detail


def test_honest_failure_claim_is_not_flagged():
    issues = contradicted_by_level(
        [("The order service failed to publish to Kafka topic orders-v1", (12,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_health_claim_citing_a_non_failure_line_is_not_flagged():
    issues = contradicted_by_level(
        [("The order service operated normally", (13,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_negated_health_phrase_is_not_read_as_health():
    """'is not healthy' asserts the opposite; firing on it would be backwards."""
    assert not asserts_no_failure("The order service is not healthy")
    issues = contradicted_by_level(
        [("The order service is not healthy", (12,))], index_evidence(RENDERED)
    )
    assert issues == []


def test_mixed_claim_is_left_alone():
    """'X is healthy but Y failed' also asserts a failure, so it is not this shape."""
    text = "The gateway is healthy but the order service failed to publish"
    assert not asserts_no_failure(text)
    assert contradicted_by_level([(text, (12,))], index_evidence(RENDERED)) == []


def test_temporally_scoped_claim_is_left_alone():
    """'no failures after 20:18' is compatible with an error at 20:17."""
    issues = contradicted_by_level(
        [("No failures were observed after the circuit breaker opened", (12,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_inferred_level_cannot_convict():
    """A severity guessed from wording must not be used to call an answer wrong."""
    inferred = ["[L9] 07:13:43 ERROR~sshd    Failed password for root"]
    issues = contradicted_by_level(
        [("The sshd service is healthy and no errors occurred", (9,))],
        index_evidence(inferred),
    )
    assert issues == []


def test_uncited_health_claim_is_not_this_checks_business():
    """With no citation there is no evidence to contradict."""
    assert (
        contradicted_by_level([("Everything is healthy", ())], index_evidence(RENDERED)) == []
    )


def test_unknown_id_is_not_this_checks_business():
    """A fabricated id is verify.py's job, not this one's."""
    assert contradicted_by_level([("All is normal", (99,))], index_evidence(RENDERED)) == []


def test_several_phrasings_of_health_are_recognised():
    for text in (
        "The service is healthy",
        "No errors were observed in the window",
        "The platform operated normally throughout",
        "The request completed without any errors",
        "Nothing was wrong with the order service",
        "The cluster remained stable",
    ):
        assert asserts_no_failure(text), text


def test_ordinary_failure_prose_is_not_health():
    for text in (
        "The order service failed to publish to Kafka",
        "Connection refused by the SMTP server",
        "The circuit breaker switched to OPEN",
    ):
        assert not asserts_no_failure(text), text


# ---------------------------------------------------------------------------
# Invented quantities: a count the cited lines cannot add up to
# ---------------------------------------------------------------------------


def test_invented_count_on_a_real_citation_is_flagged():
    """The blind spot this check exists to close."""
    issues = unsupported_counts(
        [("The order service failed to publish to Kafka 47 times during the window", (12,))],
        index_evidence(RENDERED),
    )
    assert len(issues) == 1
    assert issues[0].kind == "invented-quantity"
    assert "47 times" in issues[0].detail


def test_a_count_the_cited_lines_can_cover_is_not_flagged():
    issues = unsupported_counts(
        [("Two failures occurred, and 2 errors were logged", (12, 14))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_a_count_the_evidence_states_itself_is_not_flagged():
    """A mined pattern rendered as `[3x]` supports a count of three."""
    summary = ["  [3x] Failed to publish to Kafka\n        order-service  first at [L12]\n"]
    issues = unsupported_counts(
        [("The publish failure occurred 3 times", (12,))], index_evidence(summary)
    )
    assert issues == []


def test_a_citation_id_is_not_a_supporting_number():
    """The 12 in [L12] must not license a claim of 12 failures.

    Uses evidence where the id is still on the line — a passing mention such
    as `first at [L12]` — because that is the only place the id survives into
    the evidence text and the guard can matter.
    """
    summary = ["  [1x] Kafka publish failed\n        order-service  first at [L12]\n"]
    evidence = index_evidence(summary)
    assert "[L12]" in evidence[12].text

    issues = unsupported_counts(
        [("The order service failed 12 times in the window", (12,))], evidence
    )
    assert len(issues) == 1


def test_percentages_are_not_read_as_counts():
    issues = unsupported_counts(
        [("Errors accounted for 20% of entries in the sample", (12,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_durations_are_not_read_as_counts():
    issues = unsupported_counts(
        [("The broker did not acknowledge after 5000ms and the request failed", (12,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_uncountable_prose_is_not_flagged():
    issues = unsupported_counts(
        [("The order service failed to publish to Kafka topic orders-v1", (12,))],
        index_evidence(RENDERED),
    )
    assert issues == []


def test_unknown_ids_are_left_to_the_citation_check():
    assert unsupported_counts([("Seen 99 times", (404,))], index_evidence(RENDERED)) == []


def _recurring_error_log(tmp_path):
    """A log where one pattern recurs seven times across hosts."""
    rows = [
        json.dumps(
            {
                "timestamp": f"2026-07-30T20:1{i}:00Z",
                "level": "ERROR",
                "service": "order-service",
                "message": f"Failed to publish event to Kafka topic orders-v1 on host node-{i}",
            }
        )
        for i in range(7)
    ]
    path = tmp_path / "recurring.jsonl"
    path.write_text("\n".join(rows))
    return str(path)


def test_a_correct_count_against_real_tool_output_is_not_flagged(tmp_path):
    """The count a tool renders sits above the example line, not on it.

    `top_errors` puts `[7x]` five lines above the `example: [L1]` it belongs
    to. A check reading only the cited line would call this correct claim
    invented — the false positive that gets a verifier switched off. Built
    from the real tool so it tracks the renderer.
    """
    sources = [top_errors.invoke({"file_path": _recurring_error_log(tmp_path)})]
    assert "[7x]" in sources[0]

    issues = unsupported_counts(
        [("The Kafka publish failed 7 times across the window", (1,))],
        index_evidence(sources),
    )
    assert issues == []


def test_a_count_beyond_real_tool_output_is_still_flagged(tmp_path):
    """The block licenses the number it states, not any number."""
    sources = [top_errors.invoke({"file_path": _recurring_error_log(tmp_path)})]
    issues = unsupported_counts(
        [("The Kafka publish failed 400 times across the window", (1,))],
        index_evidence(sources),
    )
    assert len(issues) == 1
    assert "400 times" in issues[0].detail
