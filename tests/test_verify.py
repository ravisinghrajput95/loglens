"""Verification: does the answer only quote what the tools returned?"""

from loglens.verify import Report, extract_quotes, format_report, normalize, verify

# A realistic slice of what summarize_logs and top_errors hand back.
TOOL_OUTPUT = """Log file: app.log  (format: json (25))
Entries parsed: 25
Error rate: 20.0% (5 of 25)

1. [1x] Failed to publish event to Kafka topic <NAME>
   services: order-service
   exception: TimeoutException: Topic orders-v1 not acknowledged after 5000ms
   example: Failed to publish event to Kafka topic orders-v1
   trace_id: f82b719c
"""

# What llama3.2 actually produced: log lines in a format the file never used.
FABRICATED = "2026-07-30 20:15:31 INFO [kubernetes-controller] [main] Starting controller"


class TestExtractQuotes:
    def test_finds_code_spans(self):
        assert extract_quotes("The error was `connection refused here`") == [
            "connection refused here"
        ]

    def test_finds_double_quoted_text(self):
        assert "the database timed out" in extract_quotes('It said "the database timed out"')

    def test_two_code_spans_do_not_merge_into_the_prose_between_them(self):
        """Regression: a naive pattern paired the closing backtick of one span
        with the opening backtick of the next, capturing the sentence between
        them and reporting ordinary prose as a fabricated quote."""
        answer = (
            "The `order-service` failed and this long sentence sits between the "
            "spans describing what happened, then `notification-service` also failed."
        )
        quotes = extract_quotes(answer)
        assert quotes == ["order-service", "notification-service"]
        assert not any("sits between" in q for q in quotes)

    def test_short_spans_are_ignored(self):
        assert extract_quotes("levels `INFO` and `WARN` and `db`") == []

    def test_duplicates_collapse(self):
        answer = "`Failed to publish event` ... again `Failed to publish event`"
        assert len(extract_quotes(answer)) == 1

    def test_no_quotes_is_empty(self):
        assert extract_quotes("A plain answer with no quoted evidence.") == []

    def test_empty_answer(self):
        assert extract_quotes("") == []


class TestNormalize:
    def test_collapses_whitespace_and_case(self):
        assert normalize("Failed   TO\tpublish") == "failed to publish"

    def test_strips_trailing_punctuation(self):
        assert normalize("disk full.") == normalize("disk full")


class TestVerify:
    def test_real_quote_is_supported(self):
        answer = "Evidence: `Failed to publish event to Kafka topic orders-v1`"
        assert verify(answer, [TOOL_OUTPUT]).clean

    def test_fabricated_quote_is_flagged(self):
        report = verify(f"Evidence: `{FABRICATED}`", [TOOL_OUTPUT])
        assert not report.clean
        assert report.unsupported == [FABRICATED]

    def test_mixed_answer_reports_only_the_invented_part(self):
        answer = (
            "The `order-service` hit `TimeoutException: Topic orders-v1 not "
            f"acknowledged after 5000ms`, and also `{FABRICATED}`."
        )
        report = verify(answer, [TOOL_OUTPUT])
        assert report.unsupported == [FABRICATED]
        assert report.supported == 2

    def test_whitespace_and_case_differences_still_match(self):
        answer = "Evidence: `failed to publish    event to kafka topic orders-v1`"
        assert verify(answer, [TOOL_OUTPUT]).clean

    def test_tool_names_are_allowed(self):
        answer = "I called `summarize_logs` and then `trace_timeline` to check."
        assert verify(answer, [TOOL_OUTPUT], allow=["summarize_logs", "trace_timeline"]).clean

    def test_tool_names_without_the_allowance_are_flagged(self):
        report = verify("I called `summarize_logs` first.", [TOOL_OUTPUT])
        assert not report.clean

    def test_several_sources_are_all_searched(self):
        answer = "`No space left on device` caused it"
        assert verify(answer, [TOOL_OUTPUT, "exception: No space left on device"]).clean

    def test_answer_without_quotes_is_clean(self):
        report = verify("The order service timed out talking to Kafka.", [TOOL_OUTPUT])
        assert report.clean
        assert report.checked == []

    def test_no_sources_flags_everything(self):
        """With nothing retrieved, any quoted evidence is unsupported by
        definition — this is the single-tool-call fabrication case."""
        report = verify(f"Evidence: `{FABRICATED}`", [""])
        assert not report.clean


class TestFormatReport:
    def test_clean_report_says_nothing(self):
        assert format_report(Report(checked=["a"], unsupported=[])) == ""

    def test_warning_names_the_counts_and_quotes(self):
        report = Report(checked=["a", "b", "c"], unsupported=[FABRICATED])
        text = format_report(report)
        assert "1 of 3" in text
        assert FABRICATED[:40] in text

    def test_long_quotes_are_truncated(self):
        report = Report(checked=["x"], unsupported=["y" * 300])
        assert "..." in format_report(report)
        assert len(max(format_report(report).splitlines(), key=len)) < 160

    def test_many_quotes_are_summarized(self):
        report = Report(
            checked=[f"q{i}" for i in range(20)],
            unsupported=[f"fabricated line number {i}" for i in range(15)],
        )
        text = format_report(report)
        assert "and 5 more" in text


class TestEndToEndScenario:
    def test_the_observed_failure_is_caught(self):
        """The real case: one summarize_logs call, then eight invented lines."""
        summarize_output = (
            "Log file: app.log\nEntries parsed: 25\nError rate: 20.0% (5 of 25)\n"
            "  kubernetes-controller    ERROR=1 WARN=1\n"
        )
        answer = "\n".join(
            f"* Evidence: `2026-07-30 20:1{i}:01 ERROR [svc-{i}] [main] Failed thing {i}`"
            for i in range(8)
        )
        report = verify(answer, [summarize_output])
        assert len(report.unsupported) == 8
        assert "8 of 8" in format_report(report)

    def test_a_grounded_answer_passes(self):
        """gemma4's behaviour: quotes come from what the tools returned."""
        answer = (
            "The `order-service` failed with `TimeoutException: Topic orders-v1 "
            "not acknowledged after 5000ms` on trace `f82b719c`."
        )
        assert verify(answer, [TOOL_OUTPUT]).clean
