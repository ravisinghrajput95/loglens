"""Truncation behaviour and time filtering.

Both exist because the tool was answering the wrong question: it analysed the
oldest part of a large file, and it had no way to ask about a time range.
"""

from datetime import UTC, datetime, timedelta

import pytest

from loglens import analysis
from loglens.models import LogEntry
from loglens.parser import load_entries, parse_time_spec
from loglens.tools import search_logs, summarize_logs

BASE = datetime(2026, 7, 30, 20, 0, tzinfo=UTC)


def make_log(tmp_path, count, errors_at_end=0):
    """A log whose failures sit at the end, as they do during an incident."""
    lines = [
        f'{{"timestamp":"2026-07-30T20:{i // 60 % 60:02d}:{i % 60:02d}Z",'
        f'"level":"INFO","service":"svc","message":"routine event {i}"}}'
        for i in range(count - errors_at_end)
    ]
    lines += [
        f'{{"timestamp":"2026-07-30T21:{i % 60:02d}:00Z",'
        f'"level":"ERROR","service":"db","message":"connection refused {i}"}}'
        for i in range(errors_at_end)
    ]
    path = tmp_path / "big.log"
    path.write_text("\n".join(lines))
    return str(path)


class TestTailRetention:
    def test_the_tail_is_kept_not_the_head(self, tmp_path):
        """Regression: keeping the first N entries discarded the end of the
        file, which is exactly where an ongoing incident is."""
        path = make_log(tmp_path, 500, errors_at_end=20)
        result = load_entries(path, max_entries=50)

        assert len(result.entries) == 50
        assert result.truncated
        # Every retained failure must be present, since they are last.
        assert sum(1 for e in result.entries if e.is_failure) == 20

    def test_counts_cover_the_whole_file_even_when_truncated(self, tmp_path):
        path = make_log(tmp_path, 500, errors_at_end=20)
        result = load_entries(path, max_entries=50)

        assert result.total_entries == 500
        assert result.total_by_level["INFO"] == 480
        assert result.total_by_level["ERROR"] == 20
        assert result.error_rate == pytest.approx(4.0)

    def test_error_rate_is_not_computed_from_the_retained_slice(self, tmp_path):
        """The retained window is 40% failures; the file is 4%. Reporting the
        window's rate would overstate the incident tenfold."""
        path = make_log(tmp_path, 500, errors_at_end=20)
        result = load_entries(path, max_entries=50)
        window_rate = sum(1 for e in result.entries if e.is_failure) / len(result.entries)
        assert window_rate == pytest.approx(0.4)
        assert result.error_rate == pytest.approx(4.0)

    def test_untruncated_files_are_unaffected(self, tmp_path):
        path = make_log(tmp_path, 10)
        result = load_entries(path, max_entries=100)
        assert not result.truncated
        assert len(result.entries) == result.total_entries == 10

    def test_the_tool_explains_the_limitation(self, tmp_path):
        from loglens import tools

        path = make_log(tmp_path, 500, errors_at_end=20)
        tools._CACHE.clear()
        original = tools.load_entries
        tools.load_entries = lambda p, **kw: original(p, max_entries=50)
        try:
            out = summarize_logs.invoke({"file_path": path})
        finally:
            tools.load_entries = original

        assert "500 entries" in out
        assert "most recent" in out
        assert "4.0%" in out  # whole-file rate, not the window's


class TestTimeSpec:
    def test_relative_offsets(self):
        now = datetime(2026, 7, 30, 21, 0, tzinfo=UTC)
        assert parse_time_spec("30m", now) == now - timedelta(minutes=30)
        assert parse_time_spec("2h", now) == now - timedelta(hours=2)
        assert parse_time_spec("7d", now) == now - timedelta(days=7)
        assert parse_time_spec("1w", now) == now - timedelta(weeks=1)

    def test_absolute_timestamps(self):
        assert parse_time_spec("2026-07-30T20:15:00Z") == datetime(
            2026, 7, 30, 20, 15, tzinfo=UTC
        )

    def test_empty_means_unbounded(self):
        assert parse_time_spec(None) is None
        assert parse_time_spec("") is None

    def test_nonsense_is_rejected_with_guidance(self):
        with pytest.raises(ValueError, match="relative offset"):
            parse_time_spec("last tuesday")


class TestTimeWindow:
    def entries(self):
        return [
            LogEntry(
                line_no=i,
                raw="x",
                level="ERROR",
                message=f"m{i}",
                timestamp=BASE + timedelta(minutes=i),
            )
            for i in range(10)
        ]

    def test_since_excludes_earlier(self):
        kept = analysis.in_window(self.entries(), since=BASE + timedelta(minutes=5))
        assert len(kept) == 5

    def test_until_excludes_later(self):
        kept = analysis.in_window(self.entries(), until=BASE + timedelta(minutes=4))
        assert len(kept) == 5

    def test_both_bounds(self):
        kept = analysis.in_window(
            self.entries(),
            since=BASE + timedelta(minutes=3),
            until=BASE + timedelta(minutes=6),
        )
        assert len(kept) == 4

    def test_no_bounds_returns_everything(self):
        assert len(analysis.in_window(self.entries())) == 10

    def test_undated_entries_are_dropped_when_a_window_is_given(self):
        entries = self.entries() + [LogEntry(line_no=99, raw="x", level="ERROR")]
        assert len(analysis.in_window(entries, since=BASE)) == 10

    def test_search_accepts_a_window(self, json_log):
        out = search_logs.invoke({"file_path": json_log, "since": "2026-07-30T20:16:00Z"})
        assert "3 match" in out

    def test_search_reports_a_bad_time(self, json_log):
        out = search_logs.invoke({"file_path": json_log, "since": "whenever"})
        assert "Invalid time range" in out
