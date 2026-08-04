"""The tool layer: what the model actually receives, including on failure.

A tool that raises kills the agent run, so the central property here is that
every failure path returns text instead.
"""

import pytest

from loglens import tools
from loglens.tools import (
    TOOLS,
    detect_anomalies,
    search_logs,
    summarize_logs,
    top_errors,
    trace_timeline,
)


class TestToolContract:
    def test_all_tools_are_registered(self):
        assert {t.name for t in TOOLS} == {
            "summarize_logs",
            "search_logs",
            "top_errors",
            "trace_timeline",
            "detect_anomalies",
        }

    def test_every_tool_documents_itself(self):
        for tool in TOOLS:
            assert tool.description and len(tool.description) > 40

    def test_every_tool_takes_a_file_path(self):
        for tool in TOOLS:
            assert "file_path" in tool.args_schema.model_fields


class TestSummarizeLogs:
    def test_reports_counts_and_rate(self, json_log):
        out = summarize_logs.invoke({"file_path": json_log})
        assert "ERROR    2" in out
        assert "40.0%" in out

    def test_reports_detected_format(self, mixed_log):
        out = summarize_logs.invoke({"file_path": mixed_log})
        assert "logback" in out and "json" in out

    def test_services_with_failures_come_first(self, json_log):
        out = summarize_logs.invoke({"file_path": json_log})
        body = out[out.index("By service") :]
        assert body.index("order-service") < body.index("api-gateway")


class TestSearchLogs:
    def test_returns_matching_lines(self, json_log):
        out = search_logs.invoke({"file_path": json_log, "level": "ERROR"})
        assert "2 match" in out
        assert "Kafka" in out

    def test_reports_when_results_are_capped(self, tmp_path):
        path = tmp_path / "many.log"
        path.write_text(
            "\n".join(f'{{"level":"ERROR","message":"failure {i}"}}' for i in range(60))
        )
        out = search_logs.invoke({"file_path": str(path), "level": "ERROR", "limit": 10})
        assert "60 match" in out and "showing first 10" in out

    def test_limit_is_clamped_to_the_ceiling(self, tmp_path):
        path = tmp_path / "many.log"
        path.write_text(
            "\n".join(f'{{"level":"ERROR","message":"failure {i}"}}' for i in range(500))
        )
        out = search_logs.invoke({"file_path": str(path), "level": "ERROR", "limit": 10_000})
        assert len(out.splitlines()) <= tools.MAX_RETURNED_ENTRIES + 2

    def test_no_matches_is_not_an_error(self, json_log):
        out = search_logs.invoke({"file_path": json_log, "service": "nonexistent"})
        assert "No entries matched" in out

    def test_bad_regex_returns_a_message(self, json_log):
        out = search_logs.invoke({"file_path": json_log, "pattern": "[unclosed"})
        assert "Invalid search" in out


class TestTopErrors:
    def test_groups_and_counts(self, mixed_log):
        out = top_errors.invoke({"file_path": mixed_log})
        assert "[2x]" in out

    def test_clean_log_says_so(self, tmp_path):
        path = tmp_path / "clean.log"
        path.write_text('{"level":"INFO","message":"all good"}\n')
        assert "No ERROR" in top_errors.invoke({"file_path": str(path)})


class TestTraceTimeline:
    def test_renders_ordered_steps(self, json_log):
        out = trace_timeline.invoke({"file_path": json_log, "trace_id": "t-1"})
        assert "4 step(s)" in out
        assert "FAILURE" in out

    def test_unknown_trace_suggests_real_ones(self, json_log):
        out = trace_timeline.invoke({"file_path": json_log, "trace_id": "zzz"})
        assert "No entries" in out
        assert "t-1" in out


class TestDetectAnomalies:
    def test_renders_buckets(self, json_log):
        out = detect_anomalies.invoke({"file_path": json_log})
        assert "bucket" in out.lower()

    def test_zero_bucket_size_does_not_crash(self, json_log):
        out = detect_anomalies.invoke({"file_path": json_log, "bucket_seconds": 0})
        assert isinstance(out, str) and out


class TestFailuresAreReturnedNotRaised:
    """Every one of these would abort the agent run if it raised."""

    @pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
    def test_missing_file(self, tool, tmp_path):
        args = {"file_path": str(tmp_path / "nope.log")}
        if "trace_id" in tool.args_schema.model_fields:
            args["trace_id"] = "x"
        out = tool.invoke(args)
        assert isinstance(out, str)
        assert "No log file" in out

    @pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
    def test_directory_instead_of_file(self, tool, tmp_path):
        args = {"file_path": str(tmp_path)}
        if "trace_id" in tool.args_schema.model_fields:
            args["trace_id"] = "x"
        out = tool.invoke(args)
        assert isinstance(out, str)
        assert "directory" in out

    @pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
    def test_unparseable_file(self, tool, tmp_path):
        path = tmp_path / "junk.log"
        path.write_text("@@@\n###\n%%%\n")
        args = {"file_path": str(path)}
        if "trace_id" in tool.args_schema.model_fields:
            args["trace_id"] = "x"
        out = tool.invoke(args)
        assert "Parsed no log entries" in out

    @pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
    def test_empty_file(self, tool, tmp_path):
        path = tmp_path / "empty.log"
        path.write_text("")
        args = {"file_path": str(path)}
        if "trace_id" in tool.args_schema.model_fields:
            args["trace_id"] = "x"
        assert isinstance(tool.invoke(args), str)


class TestCache:
    def test_second_read_is_served_from_cache(self, json_log):
        tools._CACHE.clear()
        summarize_logs.invoke({"file_path": json_log})
        assert len(tools._CACHE) == 1
        top_errors.invoke({"file_path": json_log})
        assert len(tools._CACHE) == 1

    def test_modifying_the_file_invalidates_it(self, tmp_path):
        path = tmp_path / "live.log"
        path.write_text('{"level":"INFO","message":"one"}\n')
        assert "Entries parsed: 1" in summarize_logs.invoke({"file_path": str(path)})

        path.write_text(
            '{"level":"INFO","message":"one"}\n{"level":"ERROR","message":"two"}\n'
        )
        assert "Entries parsed: 2" in summarize_logs.invoke({"file_path": str(path)})
