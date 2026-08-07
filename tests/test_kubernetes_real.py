"""Kubernetes node files and control-plane formats, against real captures.

Everything here reads a file taken off a running cluster, not a sample written
to match the parser. The distinction earned its place: the CRI node format and
the kube-system component formats passed their synthetic tests for weeks while
reporting a healthy control plane as 100% errors.

The fixtures come from a local `kind` cluster (Kubernetes v1.36.1), which
writes exactly what a managed node does — the kubelet's CRI layout is not
cloud-specific.
"""

from pathlib import Path

import pytest

from loglens.parser import iter_entries, load_entries

FIXTURES = Path(__file__).parent / "fixtures"

NODE_FILE = FIXTURES / "cri_node_container.log"
APISERVER = FIXTURES / "cri_kube_apiserver_klog.log"
COREDNS = FIXTURES / "cri_coredns.log"


def levels(path) -> dict[str, int]:
    result = load_entries(str(path))
    return dict(result.total_by_level)


def klog_truth(path) -> dict[str, int]:
    """Severity counted straight off the klog letter, independent of the parser.

    Deliberately a second implementation. Asserting the parser against itself
    would prove nothing.
    """
    names = {"I": "INFO", "W": "WARN", "E": "ERROR", "F": "FATAL"}
    counts: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        body = line.split(" F ", 1)[-1]
        if len(body) > 5 and body[0] in names and body[1:5].isdigit():
            name = names[body[0]]
            counts[name] = counts.get(name, 0) + 1
    return counts


class TestCriNodeFile:
    """`/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log`."""

    def test_every_line_parses(self):
        total = len(NODE_FILE.read_text().strip().splitlines())
        assert load_entries(str(NODE_FILE)).total_entries == total

    def test_the_kubelet_prefix_is_stripped(self):
        first = next(iter_entries(str(NODE_FILE)))
        assert first.message == "starting up"
        assert "stdout" not in first.message
        assert first.timestamp is not None

    def test_the_applications_own_format_survives_the_prefix(self):
        """A JSON line under a CRI prefix keeps its own fields."""
        entries = list(iter_entries(str(NODE_FILE)))
        json_line = next(e for e in entries if e.service == "api")
        assert json_line.level == "ERROR"
        assert json_line.message == "upstream 502"

    def test_logfmt_under_the_prefix_keeps_its_level(self):
        entries = list(iter_entries(str(NODE_FILE)))
        logfmt = next(e for e in entries if e.service == "demo")
        assert logfmt.level == "INFO"
        assert logfmt.message == "listening on :8080"

    def test_stderr_without_a_level_of_its_own_is_read_as_a_failure(self):
        entries = list(iter_entries(str(NODE_FILE)))
        plain = next(e for e in entries if "connection refused" in e.message)
        assert plain.level == "ERROR"


class TestKlogControlPlane:
    """kube-apiserver, scheduler, controller-manager and kube-proxy."""

    def test_every_line_parses(self):
        total = len(APISERVER.read_text().strip().splitlines())
        assert load_entries(str(APISERVER)).total_entries == total

    def test_severity_matches_the_klog_letter_exactly(self):
        """The bug this file exists for.

        klog writes INFO and WARN to stderr like everything else, so reading
        the CRI stream as the severity called all 217 lines of a healthy
        apiserver an ERROR. Severity has to come from the klog letter.
        """
        truth = klog_truth(APISERVER)
        assert truth, "fixture should contain klog lines"
        got = {k: v for k, v in levels(APISERVER).items() if k in truth or v}
        assert got == truth

    def test_a_healthy_control_plane_is_not_all_errors(self):
        result = load_entries(str(APISERVER))
        assert result.error_rate < 50.0

    def test_the_source_location_is_not_read_as_a_service(self):
        """`options.go:263` is a file and line, not a service.

        Reading it as one turns a single component into one service per source
        file and makes the per-service breakdown meaningless.
        """
        services = {e.service for e in iter_entries(str(APISERVER)) if e.service}
        assert not any(s.endswith(tuple(f":{n}" for n in range(10))) for s in services)
        assert not any(".go:" in s for s in services)

    def test_a_klog_line_whose_body_is_key_value_pairs_keeps_its_severity(self):
        """logfmt is tried first and used to swallow these.

        klog event lines carry a message of key="value" pairs, which looks
        exactly like logfmt. One real kube-controller-manager INFO line was
        read as UNKNOWN because of it.
        """
        line = (
            "2026-08-07T06:28:45.437898213Z stderr F I0807 06:28:45.437755       1 "
            'event.go:389] "Event occurred" object="kube-system/kube-controller-manager" '
            'fieldPath="" kind="Lease" apiVersion="coordination.k8s.io/v1" '
            'type="Normal" reason="LeaderElection" message="became leader"'
        )
        from loglens.parser import parse_line

        entry = parse_line(line)
        assert entry is not None
        assert entry.level == "INFO", "logfmt claimed the line and lost the severity"


class TestCoreDns:
    def test_every_line_parses(self):
        total = len(COREDNS.read_text().strip().splitlines())
        assert load_entries(str(COREDNS)).total_entries == total

    def test_a_bracketed_level_with_no_timestamp_is_read(self):
        """CoreDNS writes `[INFO] plugin/reload: ...` and no clock of its own."""
        entries = list(iter_entries(str(COREDNS)))
        info = next(e for e in entries if "plugin/reload" in e.message)
        assert info.level == "INFO"

    def test_lines_that_carry_no_level_are_not_given_one(self):
        """`CoreDNS-1.14.2` is a banner, not an event."""
        entries = list(iter_entries(str(COREDNS)))
        banner = next(e for e in entries if "CoreDNS-1" in e.message)
        assert banner.level == "UNKNOWN"


@pytest.mark.parametrize("path", [NODE_FILE, APISERVER, COREDNS])
def test_nothing_is_dropped(path):
    """A parser that silently skips lines hides whatever was on them."""
    total = len(path.read_text().strip().splitlines())
    assert load_entries(str(path)).total_entries == total
