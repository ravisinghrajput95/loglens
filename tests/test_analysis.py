"""Analysis: signatures, summaries, search, error grouping, traces, anomalies."""

from datetime import UTC, datetime, timedelta

import pytest

from loglens import analysis
from loglens.models import LogEntry
from loglens.parser import load_entries

BASE = datetime(2026, 7, 30, 20, 0, 0, tzinfo=UTC)


def entry(level="INFO", service="svc", message="m", offset=0, **kwargs):
    return LogEntry(
        line_no=1,
        raw=message,
        level=level,
        service=service,
        message=message,
        timestamp=BASE + timedelta(seconds=offset),
        **kwargs,
    )


class TestSignature:
    def test_number_with_unit_suffix_is_normalized(self):
        """Regression: the pattern ended in \\b, and there is no word boundary
        between '0' and 'm', so '5000ms' survived and split one fault into
        several apparent patterns."""
        a = analysis.signature("Connection timeout after 5000ms to postgres-01")
        b = analysis.signature("Connection timeout after 3000ms to postgres-04")
        assert a == b

    @pytest.mark.parametrize(
        "left,right",
        [
            ("Pod inventory-api-74f6 crashed", "Pod inventory-api-91ab crashed"),
            ("Timeout from 10.0.0.1", "Timeout from 192.168.1.7"),
            ("Request b10a4f5e failed", "Request c92d11e4 failed"),
            ("Took 1.5s to respond", "Took 12.25s to respond"),
        ],
    )
    def test_variable_parts_collapse(self, left, right):
        assert analysis.signature(left) == analysis.signature(right)

    def test_genuinely_different_errors_stay_separate(self):
        assert analysis.signature("Disk full") != analysis.signature("Network down")

    @pytest.mark.parametrize(
        "left,right",
        [
            ("Gateway returned HTTP 503", "Gateway returned HTTP 404"),
            ("Pod exited with exit_code 137", "Pod exited with exit_code 1"),
            ("Upstream status 500", "Upstream status 429"),
        ],
    )
    def test_status_and_exit_codes_are_not_collapsed(self, left, right):
        """A 503 is an outage, a 404 is a bad route and a 429 is throttling.
        Merging them into 'HTTP <N>' reports three incidents as one."""
        assert analysis.signature(left) != analysis.signature(right)

    def test_whitespace_is_collapsed(self):
        assert analysis.signature("a   b\tc") == "a b c"


class TestSummarize:
    def test_counts_and_error_rate(self, json_log):
        result = load_entries(json_log)
        s = analysis.summarize(result.entries, result.skipped)
        assert s.total == 5
        assert s.by_level == {"INFO": 2, "WARN": 1, "ERROR": 2}
        assert s.failures == 2
        assert s.error_rate == pytest.approx(40.0)

    def test_time_range(self, json_log):
        s = analysis.summarize(load_entries(json_log).entries)
        assert s.duration == timedelta(seconds=38)

    def test_per_service_breakdown(self, json_log):
        s = analysis.summarize(load_entries(json_log).entries)
        assert s.by_service["api-gateway"]["INFO"] == 2
        assert s.by_service["order-service"]["ERROR"] == 1

    def test_fatal_counts_as_a_failure(self):
        s = analysis.summarize([entry(level="FATAL"), entry(level="INFO")])
        assert s.failures == 1
        assert s.error_rate == pytest.approx(50.0)

    def test_empty_input_does_not_divide_by_zero(self):
        s = analysis.summarize([])
        assert s.total == 0
        assert s.error_rate == 0.0
        assert s.duration is None

    def test_entries_without_timestamps(self):
        s = analysis.summarize([LogEntry(line_no=1, raw="x", level="INFO")])
        assert s.first_seen is None


class TestSearch:
    def test_filter_by_level(self, json_log):
        matches, total = analysis.search(load_entries(json_log).entries, level="ERROR")
        assert total == 2
        assert all(e.level == "ERROR" for e in matches)

    def test_error_also_returns_fatal(self):
        entries = [entry(level="ERROR"), entry(level="FATAL"), entry(level="INFO")]
        _, total = analysis.search(entries, level="ERROR")
        assert total == 2

    def test_service_is_a_substring_match(self, json_log):
        _, total = analysis.search(load_entries(json_log).entries, service="order")
        assert total == 1

    def test_pattern_is_case_insensitive(self, json_log):
        _, total = analysis.search(load_entries(json_log).entries, pattern="KAFKA")
        assert total == 1

    def test_filters_combine_with_and(self, json_log):
        entries = load_entries(json_log).entries
        _, total = analysis.search(entries, level="ERROR", service="payment")
        assert total == 1

    def test_trace_filter(self, json_log):
        _, total = analysis.search(load_entries(json_log).entries, trace_id="t-1")
        assert total == 4

    def test_limit_caps_results_but_not_the_count(self):
        entries = [entry(level="ERROR") for _ in range(30)]
        matches, total = analysis.search(entries, level="ERROR", limit=5)
        assert len(matches) == 5
        assert total == 30

    def test_no_filters_returns_everything(self, json_log):
        _, total = analysis.search(load_entries(json_log).entries)
        assert total == 5


class TestTopErrors:
    def test_similar_errors_group_with_a_count(self):
        entries = [
            entry(level="ERROR", message=f"Connection timeout after {n}ms to db-{n}")
            for n in (1000, 2000, 3000)
        ]
        groups = analysis.top_errors(entries)
        assert len(groups) == 1
        assert groups[0].count == 3

    def test_sorted_by_frequency(self):
        entries = [entry(level="ERROR", message="rare failure")] + [
            entry(level="ERROR", message=f"common failure {i}") for i in range(4)
        ]
        groups = analysis.top_errors(entries)
        assert groups[0].count == 4

    def test_ignores_non_failures(self):
        assert analysis.top_errors([entry(level="INFO"), entry(level="WARN")]) == []

    def test_collects_services_and_exceptions(self):
        entries = [
            entry(level="ERROR", service="a", message="boom", exception="E1"),
            entry(level="ERROR", service="b", message="boom", exception="E2"),
        ]
        group = analysis.top_errors(entries)[0]
        assert group.services == ["a", "b"]
        assert group.exceptions == ["E1", "E2"]

    def test_limit(self):
        # Messages must differ in more than a number, or signature grouping
        # would correctly collapse them into one group.
        words = ["disk", "network", "memory", "cpu", "socket", "cache", "quota"]
        entries = [entry(level="ERROR", message=f"{w} failure") for w in words]
        assert len(analysis.top_errors(entries, limit=3)) == 3


class TestTraceTimeline:
    def test_orders_by_time_and_computes_gaps(self):
        entries = [
            entry(offset=10, message="third", trace_id="t"),
            entry(offset=0, message="first", trace_id="t"),
            entry(offset=4, message="second", trace_id="t"),
        ]
        steps = analysis.trace_timeline(entries, "t")
        assert [s.entry.message for s in steps] == ["first", "second", "third"]
        assert steps[0].gap_ms is None
        assert steps[1].gap_ms == pytest.approx(4000)
        assert steps[2].gap_ms == pytest.approx(6000)

    def test_excludes_other_traces(self):
        entries = [entry(trace_id="a"), entry(trace_id="b")]
        assert len(analysis.trace_timeline(entries, "a")) == 1

    def test_unknown_trace_is_empty(self):
        assert analysis.trace_timeline([entry(trace_id="a")], "zzz") == []

    def test_entries_without_timestamps_sort_last(self):
        entries = [
            LogEntry(line_no=2, raw="x", trace_id="t", message="no stamp"),
            entry(offset=0, message="stamped", trace_id="t"),
        ]
        steps = analysis.trace_timeline(entries, "t")
        assert steps[-1].entry.message == "no stamp"


class TestDetectAnomalies:
    def test_flags_a_burst_of_errors(self):
        entries = [entry(offset=i) for i in range(0, 240, 20)]
        entries += [entry(level="ERROR", offset=300 + i) for i in range(8)]
        entries += [entry(offset=400 + i * 20) for i in range(5)]
        result = analysis.detect_anomalies(entries, bucket_seconds=60)
        assert result.spike_buckets

    def test_too_few_buckets_reports_instead_of_guessing(self):
        result = analysis.detect_anomalies([entry(level="ERROR")], bucket_seconds=60)
        assert result.spike_buckets == []
        assert any("bucket" in note.lower() for note in result.notes)

    def test_steady_failures_are_not_reported_as_a_spike(self):
        """mean + sigma flagged ordinary variation. A flat failure rate is not
        an anomaly however many failures it contains."""
        entries = [entry(level="ERROR", offset=minute * 60) for minute in range(20)]
        result = analysis.detect_anomalies(entries, bucket_seconds=60)
        assert result.spike_buckets == []

    def test_a_real_burst_is_still_found(self):
        entries = [entry(level="ERROR", offset=minute * 60) for minute in range(20)]
        entries += [entry(level="ERROR", offset=7 * 60 + i) for i in range(30)]
        result = analysis.detect_anomalies(entries, bucket_seconds=60)
        assert len(result.spike_buckets) == 1

    def test_too_little_latency_data_reports_instead_of_guessing(self):
        result = analysis.detect_anomalies([entry(latency_ms=100)])
        assert result.latency_outliers == []
        assert any("latency_ms" in note for note in result.notes)

    def test_latency_outliers_when_there_is_enough_data(self):
        entries = [entry(offset=i, latency_ms=100) for i in range(20)]
        entries.append(entry(offset=21, latency_ms=99000))
        result = analysis.detect_anomalies(entries)
        assert result.latency_outliers[0].latency_ms == 99000

    def test_ranks_services_by_failures(self):
        entries = [entry(level="ERROR", service="bad") for _ in range(3)]
        entries += [entry(level="ERROR", service="worse") for _ in range(5)]
        result = analysis.detect_anomalies(entries)
        assert result.worst_services[0] == ("worse", 5)

    def test_no_entries_carry_timestamps(self):
        result = analysis.detect_anomalies([LogEntry(line_no=1, raw="x", level="ERROR")])
        assert result.buckets == []
