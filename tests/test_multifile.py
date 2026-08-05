"""Reading several logs as one timeline.

An incident spans services and their logs are separate files. Following a
request across that boundary is the thing a single-file tool cannot do, so it
is the capability most worth pinning down.
"""

import pytest

from loglens import cli
from loglens.parser import load_many
from loglens.report import crossings, render, sources


@pytest.fixture
def service_logs(tmp_path):
    """Three services, one request, interleaved in time across the files."""
    (tmp_path / "gateway.log").write_text(
        '{"timestamp":"2026-07-30T20:15:31.000Z","level":"INFO","service":"api-gateway",'
        '"message":"POST /checkout received","trace_id":"chk-99"}\n'
        '{"timestamp":"2026-07-30T20:15:39.400Z","level":"ERROR","service":"api-gateway",'
        '"message":"Upstream returned 502","trace_id":"chk-99"}\n'
    )
    (tmp_path / "inventory.log").write_text(
        '{"timestamp":"2026-07-30T20:15:32.100Z","level":"INFO","service":"inventory",'
        '"message":"Reserve request received","trace_id":"chk-99"}\n'
        '{"timestamp":"2026-07-30T20:15:37.000Z","level":"ERROR","service":"inventory",'
        '"message":"Connection timeout after 5000ms to postgres-01","trace_id":"chk-99"}\n'
    )
    (tmp_path / "orders.log").write_text(
        "2026-07-30 20:15:35,000 ERROR [order-service] Failed to reserve inventory\n"
    )
    return [
        str(tmp_path / "gateway.log"),
        str(tmp_path / "inventory.log"),
        str(tmp_path / "orders.log"),
    ]


class TestMerge:
    def test_entries_from_every_file_are_present(self, service_logs):
        assert load_many(service_logs).total_entries == 5

    def test_merged_in_time_order_not_file_order(self, service_logs):
        result = load_many(service_logs)
        stamps = [e.timestamp for e in result.entries]
        assert stamps == sorted(stamps)
        # The first entry comes from gateway, the second from inventory.
        assert result.entries[0].source == "gateway.log"
        assert result.entries[1].source == "inventory.log"

    def test_each_entry_knows_its_file(self, service_logs):
        assert {e.source for e in load_many(service_logs).entries} == {
            "gateway.log",
            "inventory.log",
            "orders.log",
        }

    def test_citation_ids_are_unique_across_files(self, service_logs):
        """Line numbers repeat across files, so an unrenumbered merge would
        give two different entries the same citation."""
        entries = load_many(service_logs).entries
        ids = [e.citation_id for e in entries]
        assert len(ids) == len(set(ids))

    def test_the_original_file_and_line_survive(self, service_logs):
        entry = load_many(service_logs).entries[0]
        assert entry.line_no == 1
        assert "gateway.log:1" in entry.cite()

    def test_counters_are_summed(self, service_logs):
        result = load_many(service_logs)
        assert result.total_by_level["ERROR"] == 3
        assert result.total_by_level["INFO"] == 2
        assert result.error_rate == pytest.approx(60.0)

    def test_formats_from_every_file_are_recorded(self, service_logs):
        assert set(load_many(service_logs).formats) == {"json", "logback"}

    def test_a_single_file_behaves_as_before(self, json_log):
        result = load_many([json_log])
        assert result.total_entries == 5
        # No merge happened, so nothing is renumbered or relabelled.
        assert all(e.uid == 0 and e.source == "" for e in result.entries)

    def test_undated_entries_sort_last(self, tmp_path):
        (tmp_path / "a.log").write_text(
            '{"timestamp":"2026-07-30T20:00:00Z","level":"INFO","message":"dated"}\n'
        )
        (tmp_path / "b.log").write_text('{"level":"ERROR","message":"undated"}\n')
        entries = load_many([str(tmp_path / "a.log"), str(tmp_path / "b.log")]).entries
        assert entries[-1].message == "undated"


class TestTraceAcrossFiles:
    def test_a_trace_is_reconstructed_across_files(self, service_logs):
        from loglens import analysis

        steps = analysis.trace_timeline(load_many(service_logs).entries, "chk-99")
        assert len(steps) == 4
        assert {s.entry.source for s in steps} == {"gateway.log", "inventory.log"}

    def test_the_report_names_traces_that_cross_files(self, service_logs):
        entries = load_many(service_logs).entries
        text = "\n".join(crossings(entries))
        assert "chk-99" in text
        assert "gateway.log" in text and "inventory.log" in text

    def test_a_trace_inside_one_file_is_not_called_a_crossing(self, json_log):
        from loglens.parser import load_entries

        assert crossings(load_entries(json_log).entries) == []


class TestReportSections:
    def test_files_section_appears_only_for_several_files(self, service_logs, json_log):
        from loglens.parser import load_entries

        assert sources(load_many(service_logs).entries)
        assert sources(load_entries(json_log).entries) == []

    def test_files_are_ordered_by_failures(self, tmp_path):
        (tmp_path / "quiet.log").write_text(
            '{"timestamp":"2026-07-30T20:00:00Z","level":"INFO","message":"fine"}\n'
        )
        (tmp_path / "noisy.log").write_text(
            "\n".join(
                f'{{"timestamp":"2026-07-30T20:0{i}:00Z","level":"ERROR",'
                f'"message":"failure {i}"}}'
                for i in range(3)
            )
        )
        lines = sources(
            load_many([str(tmp_path / "quiet.log"), str(tmp_path / "noisy.log")]).entries
        )
        assert "noisy.log" in lines[0]
        assert "quiet.log" in lines[1]

    def test_ordering_is_stable_when_files_tie(self, service_logs):
        """Every file here has one failure. Ties must break by name, not by
        whichever order the dictionary happened to be built in."""
        first = sources(load_many(service_logs).entries)
        second = sources(load_many(service_logs).entries)
        assert first == second
        assert "gateway.log" in first[0]

    def test_rendered_report_includes_both_sections(self, service_logs):
        text = render(load_many(service_logs), "3 files")
        assert "FILES" in text
        assert "Traces crossing file boundaries" in text


class TestCommand:
    def test_several_files_are_accepted(self, service_logs, capsys):
        assert cli.main(["report", *service_logs]) == 0
        out = capsys.readouterr().out
        assert "3 files" in out
        assert "FILES" in out

    def test_one_missing_file_names_the_missing_one(self, service_logs, tmp_path, capsys):
        paths = [*service_logs, str(tmp_path / "absent.log")]
        assert cli.main(["report", *paths]) == 1
        assert "absent.log" in capsys.readouterr().err

    def test_a_single_file_still_uses_its_own_name(self, json_log, capsys):
        cli.main(["report", json_log])
        assert json_log in capsys.readouterr().out
