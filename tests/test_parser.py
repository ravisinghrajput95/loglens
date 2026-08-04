"""Parsing: formats, timestamps, stack traces, and file handling."""

import pytest

from loglens.models import normalize_level
from loglens.parser import load_entries, parse_line, parse_timestamp


class TestFormats:
    @pytest.mark.parametrize(
        "line,level,service,message",
        [
            (
                '{"timestamp":"2026-07-30T20:15:31Z","level":"ERROR","service":"db","message":"boom"}',
                "ERROR",
                "db",
                "boom",
            ),
            (
                "2026-07-30 20:15:31,123 ERROR [order-service] com.foo.Bar - Kafka publish failed",
                "ERROR",
                "order-service",
                "Kafka publish failed",
            ),
            (
                "2026/07/30 20:15:31 [error] 1234#0: *1 upstream timed out",
                "ERROR",
                "nginx",
                "*1 upstream timed out",
            ),
            (
                "[2026-07-30T20:15:31Z] [WARN] [api-gateway] Rate limit reached",
                "WARN",
                "api-gateway",
                "Rate limit reached",
            ),
            (
                "2026-07-30 20:15:31 WARNING: disk usage high",
                "WARN",
                None,
                "disk usage high",
            ),
        ],
        ids=["json", "logback", "nginx", "bracketed", "loose"],
    )
    def test_recognised_formats(self, line, level, service, message):
        entry = parse_line(line, 1)
        assert entry is not None
        assert entry.level == level
        assert entry.service == service
        assert entry.message == message
        assert entry.timestamp is not None

    def test_syslog_has_service_and_host_but_no_level(self):
        entry = parse_line("Jul 30 20:15:31 web-01 sshd[1234]: Failed password", 1)
        assert entry is not None
        assert entry.service == "sshd"
        assert entry.host == "web-01"
        # syslog carries no level field, and inventing one would be a lie.
        assert entry.level == "UNKNOWN"

    def test_json_keeps_unmodelled_fields(self):
        entry = parse_line('{"level":"ERROR","message":"x","pod":"api-7f6d","exit_code":1}', 1)
        assert entry.extra == {"pod": "api-7f6d", "exit_code": 1}

    def test_json_latency_aliases(self):
        for key in ("latency_ms", "duration_ms", "elapsed_ms"):
            entry = parse_line(f'{{"level":"INFO","message":"x","{key}":42}}', 1)
            assert entry.latency_ms == 42.0


class TestProseIsNotALogLine:
    """Regression: the loose pattern used to match level words inside prose,
    turning ordinary sentences into ERROR entries and inflating error counts."""

    @pytest.mark.parametrize(
        "line",
        [
            "The error was caused by a misconfiguration in the upstream service",
            "just some random text with no structure whatsoever",
            "we saw a warning about this last week during the incident review",
            "",
            "   ",
        ],
    )
    def test_prose_is_rejected(self, line):
        assert parse_line(line, 1) is None

    def test_line_initial_level_is_still_accepted(self):
        entry = parse_line("ERROR could not reach database", 1)
        assert entry is not None
        assert entry.level == "ERROR"


class TestTimestamps:
    @pytest.mark.parametrize(
        "value",
        [
            "2026-07-30T20:15:31Z",
            "2026-07-30T20:15:31+00:00",
            "2026-07-30 20:15:31,123",
            "2026-07-30 20:15:31.123",
            "2026/07/30 20:15:31",
            "Jul 30 20:15:31",
        ],
    )
    def test_parses_common_formats(self, value):
        assert parse_timestamp(value) is not None

    def test_every_timestamp_is_timezone_aware(self):
        """Regression: mixing aware and naive timestamps made min() raise
        TypeError, which crashed every tool on a mixed-format file."""
        for value in ["2026-07-30T20:15:31Z", "2026-07-30 20:15:31,123", "Jul 30 20:15:31"]:
            assert parse_timestamp(value).tzinfo is not None

    def test_epoch_seconds_and_millis(self):
        assert parse_timestamp(1782000000).year == 2026
        assert parse_timestamp(1782000000000).year == 2026

    @pytest.mark.parametrize("value", ["not a date", "", None, [], {}])
    def test_unparseable_returns_none(self, value):
        assert parse_timestamp(value) is None

    def test_preserves_offset(self):
        parsed = parse_timestamp("2026-07-30T20:15:31+05:30")
        assert parsed.utcoffset().total_seconds() == 5.5 * 3600


class TestLevelNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("warning", "WARN"),
            ("WARNING", "WARN"),
            ("err", "ERROR"),
            ("SEVERE", "ERROR"),
            ("critical", "FATAL"),
            ("emerg", "FATAL"),
            ("notice", "INFO"),
            ("trace", "DEBUG"),
            ("info", "INFO"),
            ("nonsense", "UNKNOWN"),
            (None, "UNKNOWN"),
            (42, "UNKNOWN"),
        ],
    )
    def test_aliases(self, raw, expected):
        assert normalize_level(raw) == expected


class TestStackTraces:
    def test_trace_folds_into_the_entry_above(self, java_log):
        result = load_entries(java_log)
        assert len(result.entries) == 3
        assert result.skipped == 0

        error = result.entries[1]
        assert error.level == "ERROR"
        assert len(error.detail) == 5

    def test_exception_comes_from_the_trace_header(self, java_log):
        """Regression: the header line is not indented, so indentation alone
        missed it and the inner 'Caused by' was reported as the exception."""
        error = load_entries(java_log).entries[1]
        assert error.exception == "java.net.SocketTimeoutException: Read timed out"

    def test_entries_after_a_trace_are_still_parsed(self, java_log):
        assert load_entries(java_log).entries[2].message == "Request completed"


class TestFileHandling:
    def test_gzip_matches_plaintext(self, json_log, gzipped_log):
        assert len(load_entries(gzipped_log).entries) == len(load_entries(json_log).entries)

    def test_mixed_formats_are_all_detected(self, mixed_log):
        result = load_entries(mixed_log)
        assert len(result.entries) == 4
        assert set(result.formats) == {"json", "logback", "syslog"}

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.log"
        path.write_text("")
        result = load_entries(str(path))
        assert result.entries == []
        assert result.total_lines == 0

    def test_blank_lines_are_not_counted(self, tmp_path):
        path = tmp_path / "blanks.log"
        path.write_text('\n\n{"level":"INFO","message":"x"}\n\n\n')
        result = load_entries(str(path))
        assert len(result.entries) == 1
        assert result.total_lines == 1

    def test_unreadable_lines_are_counted_as_skipped(self, tmp_path):
        path = tmp_path / "junk.log"
        path.write_text('{"level":"INFO","message":"ok"}\n@@@ not a log line @@@\n')
        result = load_entries(str(path))
        assert len(result.entries) == 1
        assert result.skipped == 1

    def test_cap_truncates_and_says_so(self, tmp_path):
        path = tmp_path / "big.log"
        path.write_text("\n".join(f'{{"level":"INFO","message":"m{i}"}}' for i in range(500)))
        result = load_entries(str(path), max_entries=100)
        assert len(result.entries) == 100
        assert result.truncated is True

    def test_no_truncation_below_the_cap(self, json_log):
        assert load_entries(json_log, max_entries=1000).truncated is False

    def test_invalid_utf8_does_not_raise(self, tmp_path):
        path = tmp_path / "bad.log"
        path.write_bytes(b'{"level":"INFO","message":"caf\xe9"}\n')
        assert len(load_entries(str(path)).entries) == 1

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_entries(str(tmp_path / "nope.log"))
