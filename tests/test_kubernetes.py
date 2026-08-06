"""Logs as they arrive from Kubernetes, on EKS, AKS and GKE.

None of those platforms hands you a file. They route to CloudWatch, Azure
Monitor and Cloud Logging, so what matters is whether what comes back out is
readable. Before this, `kubectl logs` of a well-behaved application worked and
every cloud export envelope did not: Azure's fields were capitalised so nothing
matched, Google nested the payload one level down so the message came out
empty, and the node-level container format was not recognised at all.
"""

import pytest

from loglens.parser import load_entries, parse_line


class TestKubectlLogs:
    def test_plain_application_output(self):
        """`kubectl logs` returns whatever the container wrote, unchanged."""
        entry = parse_line(
            '{"timestamp":"2026-08-05T10:00:09Z","level":"ERROR",'
            '"service":"api","message":"upstream connect error"}',
            1,
        )
        assert entry.level == "ERROR"
        assert entry.service == "api"

    def test_timestamps_flag_keeps_the_application_fields(self):
        """--timestamps prefixes the kubelet's clock. The prefix is stripped and
        the container's own line parsed, so its fields survive."""
        entry = parse_line(
            '2026-08-05T10:00:09.987654321Z {"level":"ERROR","service":"api",'
            '"message":"upstream connect error"}',
            1,
        )
        assert entry is not None
        assert entry.level == "ERROR"
        assert entry.service == "api"
        assert entry.message == "upstream connect error"

    def test_timestamps_flag_over_a_text_format(self):
        entry = parse_line(
            "2026-08-05T10:00:09.987654321Z 2026-08-05 10:00:09,123 ERROR [api] boom", 1
        )
        assert entry.level == "ERROR"
        assert entry.service == "api"

    def test_the_container_clock_wins_over_the_kubelet_clock(self):
        entry = parse_line(
            '2026-08-05T11:00:00.000000000Z {"timestamp":"2026-08-05T10:00:00Z",'
            '"level":"INFO","message":"x"}',
            1,
        )
        assert entry.timestamp.hour == 10


class TestContainerRuntimeFiles:
    """/var/log/pods/<pod>/<container>/0.log, written by the kubelet."""

    def test_cri_line_is_recognised(self):
        entry = parse_line(
            "2026-08-05T10:00:01.123456789Z stdout F Server listening on port 8080", 1
        )
        assert entry is not None
        assert entry.message == "Server listening on port 8080"
        assert entry.timestamp is not None

    def test_stderr_is_read_as_a_failure(self):
        """The runtime recorded which stream this came from. Using that is not
        the same as guessing severity from wording."""
        entry = parse_line("2026-08-05T10:00:09.987654321Z stderr F connection refused", 1)
        assert entry.level == "ERROR"

    def test_stdout_is_not_assumed_to_be_healthy(self):
        entry = parse_line("2026-08-05T10:00:01.123456789Z stdout F starting", 1)
        assert entry.level == "UNKNOWN"

    def test_docker_json_file_driver(self):
        entry = parse_line(
            '{"log":"connection refused\\n","stream":"stderr",'
            '"time":"2026-08-05T10:00:09.987654321Z"}',
            1,
        )
        assert entry.message == "connection refused"
        assert entry.level == "ERROR"
        assert entry.timestamp is not None


class TestGoogleCloudLogging:
    """GKE, via `gcloud logging read --format=json`."""

    def test_json_payload_is_unwrapped(self):
        entry = parse_line(
            '{"severity":"ERROR","timestamp":"2026-08-05T10:00:09.987654321Z",'
            '"resource":{"type":"k8s_container","labels":{"container_name":"api",'
            '"namespace_name":"prod"}},"jsonPayload":{"message":"upstream connect error",'
            '"trace_id":"chk-99"}}',
            1,
        )
        assert entry.level == "ERROR"
        assert entry.message == "upstream connect error"
        assert entry.service == "api"
        assert entry.trace_id == "chk-99"

    def test_text_payload(self):
        entry = parse_line(
            '{"severity":"INFO","timestamp":"2026-08-05T10:00:01.111Z",'
            '"textPayload":"Server listening on port 8080"}',
            1,
        )
        assert entry.message == "Server listening on port 8080"

    def test_an_outer_field_is_not_overwritten_by_the_envelope(self):
        entry = parse_line(
            '{"severity":"ERROR","message":"outer","jsonPayload":{"message":"inner"}}', 1
        )
        assert entry.message == "outer"


class TestAzureLogAnalytics:
    """AKS, via ContainerLogV2. Every field is capitalised."""

    def test_capitalised_fields_are_matched(self):
        entry = parse_line(
            '{"TimeGenerated":"2026-08-05T10:00:09.987Z","Computer":"aks-node-0",'
            '"ContainerName":"api","PodName":"api-7f6d","LogLevel":"error",'
            '"LogSource":"stderr","LogMessage":"upstream connect error"}',
            1,
        )
        assert entry.level == "ERROR"
        assert entry.message == "upstream connect error"
        assert entry.service == "api"
        assert entry.host == "aks-node-0"
        assert entry.timestamp is not None


class TestCloudWatch:
    """EKS, via a CloudWatch Logs export."""

    def test_epoch_millis_and_stream_name(self):
        entry = parse_line(
            '{"timestamp":1785924009987,"message":"upstream connect error",'
            '"logStreamName":"api-7f6d"}',
            1,
        )
        assert entry.message == "upstream connect error"
        assert entry.service == "api-7f6d"
        assert entry.timestamp is not None


class TestKubernetesAudit:
    """Control-plane audit logs, which every managed platform can ship."""

    AUDIT = (
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata",'
        '"stage":"ResponseComplete","requestURI":"/api/v1/namespaces/prod/pods",'
        '"verb":"list","user":{"username":"system:node:ip-10-0-1-2"},'
        '"responseStatus":{"code":403},'
        '"requestReceivedTimestamp":"2026-08-05T10:00:09.987654Z"}'
    )

    def test_the_event_becomes_readable(self):
        """An audit event has no message field; it is spread across verb,
        requestURI and responseStatus. Left alone it parses as empty, which is
        the shape that hides an RBAC denial."""
        entry = parse_line(self.AUDIT, 1)
        assert "list" in entry.message
        assert "/api/v1/namespaces/prod/pods" in entry.message
        assert "403" in entry.message
        assert "system:node:ip-10-0-1-2" in entry.message

    def test_severity_comes_from_the_response_code(self):
        assert parse_line(self.AUDIT, 1).level == "WARN"

    def test_audit_verbosity_is_not_mistaken_for_severity(self):
        """An audit event's "level" is Metadata or RequestResponse — how much
        was recorded, not how bad it was."""
        entry = parse_line(self.AUDIT, 1)
        assert entry.level != "UNKNOWN"
        assert entry.level in ("INFO", "WARN", "ERROR")

    @pytest.mark.parametrize(
        "code,expected", [(200, "INFO"), (403, "WARN"), (404, "WARN"), (500, "ERROR")]
    )
    def test_code_maps_to_level(self, code, expected):
        line = (
            '{"apiVersion":"audit.k8s.io/v1","verb":"get","requestURI":"/x",'
            f'"responseStatus":{{"code":{code}}}}}'
        )
        assert parse_line(line, 1).level == expected


class TestEndToEnd:
    @pytest.mark.parametrize(
        "name,content",
        [
            (
                "gke",
                '{"severity":"ERROR","timestamp":"2026-08-05T10:00:09Z",'
                '"resource":{"labels":{"container_name":"api"}},'
                '"jsonPayload":{"message":"connection refused"}}',
            ),
            (
                "aks",
                '{"TimeGenerated":"2026-08-05T10:00:09Z","ContainerName":"api",'
                '"LogLevel":"error","LogMessage":"connection refused"}',
            ),
            (
                "cri",
                "2026-08-05T10:00:09.987654321Z stderr F connection refused",
            ),
        ],
    )
    def test_a_failure_is_visible_in_the_report(self, tmp_path, name, content):
        from loglens.report import render

        path = tmp_path / f"{name}.log"
        path.write_text(content + "\n")
        result = load_entries(str(path))

        assert result.total_failures == 1
        assert "connection refused" in render(result, str(path))
