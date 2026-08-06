"""Formats found by running the parser over real logs.

Before this, the parser was validated only against logs written for it. Pointed
at fourteen real corpora — Loghub's Apache, HDFS, Hadoop, Spark, Zookeeper,
OpenStack, OpenSSH, Linux, Mac, Thunderbird, Proxifier, HealthApp, plus this
machine's installer and Ollama logs — six of them parsed at zero percent.

The lines below have the shape of those formats with synthetic content. Each
one is a format that used to be discarded silently.
"""

import pytest

from loglens.parser import infer_level, load_entries, parse_line, parse_timestamp
from loglens.report import render


class TestFormatsFoundInRealLogs:
    @pytest.mark.parametrize(
        "line,level,service,message_fragment",
        [
            (
                # Ollama, Docker, Grafana, Loki — the whole Go ecosystem.
                'time=2026-07-30T23:07:30.350+05:30 level=INFO source=app.go:217 msg="starting server"',
                "INFO",
                "app.go:217",
                "starting server",
            ),
            (
                # Spark, and most JVM tooling.
                "17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered handlers",
                "INFO",
                "executor.CoarseGrainedExecutorBackend",
                "Registered handlers",
            ),
            (
                # HDFS.
                "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block",
                "INFO",
                "dfs.DataNode$PacketResponder",
                "PacketResponder 1 for block",
            ),
            (
                # OpenStack, which prefixes every line with its source file.
                "nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO "
                "nova.osapi_compute.wsgi.server request completed",
                "INFO",
                "nova.osapi_compute.wsgi.server",
                "request completed",
            ),
            (
                # Proxifier, whose program names carry a bitness suffix.
                "[10.30 16:49:06] chrome.exe - proxy.example.com:5070 open through proxy",
                "UNKNOWN",
                "chrome.exe",
                "open through proxy",
            ),
            (
                # HealthApp and many mobile SDKs.
                "20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579",
                "UNKNOWN",
                "Step_LSC",
                "onStandStepChanged 3579",
            ),
            (
                # Gin, the Go HTTP framework.
                '[GIN] 2026/07/30 - 23:07:31 | 200 | 209.291µs | 127.0.0.1 | GET "/api/version"',
                "INFO",
                "gin",
                "/api/version",
            ),
        ],
        ids=["logfmt", "spark", "hdfs", "openstack", "proxifier", "pipe", "gin"],
    )
    def test_format_is_recognised(self, line, level, service, message_fragment):
        entry = parse_line(line, 1)
        assert entry is not None, "line was discarded entirely"
        assert entry.level == level
        assert entry.service == service
        assert message_fragment in entry.message
        assert entry.timestamp is not None

    def test_macos_program_names_may_contain_spaces(self):
        entry = parse_line(
            "2026-06-03 10:52:41-07 localhost Installer Progress[57]: Progress UI Starting", 1
        )
        assert entry is not None
        assert entry.service == "Installer Progress"
        assert entry.host == "localhost"

    def test_thunderbird_and_bgl_supercomputer_format(self):
        entry = parse_line(
            "- 1131566461 2005.11.09 dn228 Nov 9 12:01:01 dn228/dn228 crond[2915]: "
            "session closed for user root",
            1,
        )
        assert entry is not None
        assert entry.service == "crond"
        assert "session closed" in entry.message

    def test_syslog_programs_with_parentheses(self):
        """Linux syslog writes sshd(pam_unix), which the old pattern rejected."""
        entry = parse_line(
            "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure", 1
        )
        assert entry is not None
        assert entry.service == "sshd(pam_unix)"

    def test_syslog_daemon_announcing_its_version(self):
        entry = parse_line("Jun 19 04:09:11 combo syslogd 1.4.1: restart.", 1)
        assert entry is not None
        assert "restart" in entry.message

    def test_macos_trailing_subsystem_group(self):
        entry = parse_line(
            "Jul  2 16:55:53 host com.apple.xpc.launchd[1] (com.apple.xpc.domain): "
            "service exited",
            1,
        )
        assert entry is not None
        assert "service exited" in entry.message


class TestGinSeverityFromStatus:
    """An access log states its outcome as a status code. Reading it is not the
    same as inventing a severity the line never carried."""

    @pytest.mark.parametrize(
        "status,expected",
        [("200", "INFO"), ("301", "INFO"), ("404", "WARN"), ("429", "WARN"), ("500", "ERROR")],
    )
    def test_status_maps_to_level(self, status, expected):
        line = f'[GIN] 2026/07/30 - 23:07:31 | {status} | 1ms | 127.0.0.1 | GET "/x"'
        assert parse_line(line, 1).level == expected


class TestLogfmt:
    def test_quoted_values_with_spaces(self):
        entry = parse_line('level=error msg="could not reach the database" service=api', 1)
        assert entry.message == "could not reach the database"
        assert entry.level == "ERROR"

    def test_error_field_becomes_the_exception(self):
        entry = parse_line('level=error msg="failed" err="dial tcp: refused"', 1)
        assert entry.exception == "dial tcp: refused"

    def test_unmodelled_keys_are_kept(self):
        entry = parse_line('level=info msg="ok" region=eu-west-1 attempt=3', 1)
        assert entry.extra["region"] == "eu-west-1"

    def test_a_line_without_level_or_msg_is_not_logfmt(self):
        assert parse_line("foo=1 bar=2 baz=3", 1) is None


class TestNewTimestamps:
    @pytest.mark.parametrize(
        "value,year",
        [
            ("081109 203615", 2008),
            ("17/06/09 20:10:40", 2017),
            ("20171223-22:15:29:606", 2017),
            ("2017-05-16 00:00:00.008", 2017),
            ("2026-06-03 10:52:41-07", 2026),
            ("2026/07/30 - 23:07:31", 2026),
        ],
    )
    def test_parses(self, value, year):
        parsed = parse_timestamp(value)
        assert parsed is not None
        assert parsed.year == year

    def test_two_digit_offset_is_widened(self):
        """macOS writes -07 where strptime wants -0700."""
        parsed = parse_timestamp("2026-06-03 10:52:41-07")
        assert parsed.utcoffset().total_seconds() == -7 * 3600


class TestNoFalsePositivesFromTheNewPatterns:
    """Nine new patterns is nine new ways to mistake prose for a log line."""

    @pytest.mark.parametrize(
        "line",
        [
            "The error was caused by a misconfiguration in the upstream service",
            "just some random text with no structure whatsoever",
            "we saw a warning about this last week during the incident review",
            "See https://example.com/docs for more information about this",
            "TODO: fix the retry logic before the next release",
            "| column | column | column |",
            "-------------------------------------",
            "foo=bar",
        ],
    )
    def test_prose_and_noise_are_still_rejected(self, line):
        assert parse_line(line, 1) is None


class TestInferredSeverity:
    @pytest.mark.parametrize(
        "message,expected",
        [
            ("Failed password for root from 10.0.0.1", "ERROR"),
            ("authentication failure; logname= uid=0", "ERROR"),
            ("Connection refused by upstream", "ERROR"),
            ("unable to allocate memory", "ERROR"),
            ("no space left on device", "ERROR"),
            ("retrying request after backoff", "WARN"),
            ("disk usage exceeded threshold", "WARN"),
            ("deprecated configuration key in use", "WARN"),
            ("Accepted publickey for user", "INFO"),
            ("session opened for user root", "INFO"),
        ],
    )
    def test_wording_maps_to_a_level(self, message, expected):
        assert infer_level(message) == expected

    def test_error_wins_over_warn_when_both_appear(self):
        assert infer_level("retrying after connection refused") == "ERROR"

    def test_inference_is_off_by_default(self, tmp_path):
        path = tmp_path / "sys.log"
        path.write_text("Jun 14 15:16:01 combo sshd[123]: authentication failure\n")
        result = load_entries(str(path))
        assert result.entries[0].level == "UNKNOWN"
        assert not result.entries[0].level_inferred

    def test_inference_when_asked_for(self, tmp_path):
        path = tmp_path / "sys.log"
        path.write_text("Jun 14 15:16:01 combo sshd[123]: authentication failure\n")
        result = load_entries(str(path), infer_severity=True)
        entry = result.entries[0]
        assert entry.level == "ERROR"
        assert entry.level_inferred

    def test_a_real_level_is_never_overwritten(self, tmp_path):
        path = tmp_path / "mixed.log"
        path.write_text('{"level":"INFO","message":"connection refused but handled"}\n')
        result = load_entries(str(path), infer_severity=True)
        assert result.entries[0].level == "INFO"
        assert not result.entries[0].level_inferred

    def test_inferred_entries_are_marked_in_output(self, tmp_path):
        path = tmp_path / "sys.log"
        path.write_text("Jun 14 15:16:01 combo sshd[123]: authentication failure\n")
        entry = load_entries(str(path), infer_severity=True).entries[0]
        assert "~" in entry.one_line()


class TestSeverityHonesty:
    """A format with no severity field must not be reported as having no errors."""

    @pytest.fixture
    def syslog_file(self, tmp_path):
        path = tmp_path / "auth.log"
        path.write_text(
            "\n".join(
                f"Jun 14 15:16:{i:02d} combo sshd[{i}]: authentication failure for root"
                for i in range(10)
            )
        )
        return str(path)

    def test_unknown_share_is_measured(self, syslog_file):
        result = load_entries(syslog_file)
        assert result.unknown_share == 1.0
        assert not result.has_severity

    def test_a_json_log_does_have_severity(self, json_log):
        assert load_entries(json_log).has_severity

    def test_report_refuses_to_state_a_rate_it_cannot_compute(self, syslog_file):
        """Regression: an SSH log of 2000 authentication failures was summarised
        as '0.0% errors', because syslog carries no level field."""
        text = render(load_entries(syslog_file), syslog_file)
        assert "0.0% errors" not in text
        assert "no severity field" in text

    def test_report_explains_the_alternative(self, syslog_file):
        text = render(load_entries(syslog_file), syslog_file)
        assert "--infer-severity" in text

    def test_report_states_a_rate_once_inferred(self, syslog_file):
        text = render(load_entries(syslog_file, infer_severity=True), syslog_file)
        assert "100.0% errors" in text
        assert "inferred from message wording" in text


class TestCommandFlag:
    def test_flag_is_accepted_and_changes_the_output(self, tmp_path, capsys):
        from loglens import cli

        path = tmp_path / "auth.log"
        path.write_text("Jun 14 15:16:01 combo sshd[1]: authentication failure\n")

        assert cli.main(["report", str(path)]) == 0
        assert "no severity field" in capsys.readouterr().out

        assert cli.main(["report", str(path), "--infer-severity"]) == 0
        out = capsys.readouterr().out
        assert "100.0% errors" in out
