"""Parse coverage across log formats found in the wild.

The corpora this was derived from are Loghub's, plus logs from the machine it
was developed on. Those files are not vendored — they are large and not ours —
so what is checked here is one representative line per format, in the shape the
real file uses. If a pattern regresses, this fails without needing a download.

The percentages in the README come from running the parser over the full
corpora; this guards the shapes.
"""

from dataclasses import dataclass

from loglens.parser import parse_line


@dataclass
class Sample:
    corpus: str
    line: str
    expect_level: str | None = None
    expect_service: str | None = None


SAMPLES: list[Sample] = [
    Sample("Apache", "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok", None, None),
    Sample(
        "HDFS",
        "081109 203615 148 INFO dfs.DataNode$PacketResponder: Received block blk_1",
        "INFO",
        "dfs.DataNode$PacketResponder",
    ),
    Sample(
        "Hadoop",
        "2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster",
        "INFO",
        "main",
    ),
    Sample(
        "Spark",
        "17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Started daemon",
        "INFO",
        "executor.CoarseGrainedExecutorBackend",
    ),
    Sample(
        "OpenStack",
        "nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO "
        "nova.osapi_compute.wsgi.server request finished",
        "INFO",
        "nova.osapi_compute.wsgi.server",
    ),
    Sample(
        "OpenSSH",
        "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 10.0.0.1 port 1 ssh2",
        "UNKNOWN",
        "sshd",
    ),
    Sample(
        "Linux",
        "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; uid=0",
        "UNKNOWN",
        "sshd(pam_unix)",
    ),
    Sample(
        "Mac",
        "Jul  2 16:55:53 host com.apple.xpc.launchd[1] (com.apple.xpc.domain): exited",
        "UNKNOWN",
        "com.apple.xpc.launchd",
    ),
    Sample(
        "Thunderbird",
        "- 1131566461 2005.11.09 dn228 Nov 9 12:01:01 dn228/dn228 crond[2915]: session closed",
        "UNKNOWN",
        "crond",
    ),
    Sample(
        "Proxifier",
        "[10.30 16:49:06] chrome.exe - proxy.example.com:5070 open through proxy",
        "UNKNOWN",
        "chrome.exe",
    ),
    Sample(
        "HealthApp",
        "20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579",
        "UNKNOWN",
        "Step_LSC",
    ),
    Sample(
        "Zookeeper",
        "2015-07-29 17:41:41,648 - INFO  [main:QuorumPeer@1019] - tickTime set to 2000",
        "INFO",
        None,
    ),
    Sample(
        "Ollama (logfmt)",
        'time=2026-07-30T23:07:30.350+05:30 level=INFO source=app.go:217 msg="starting"',
        "INFO",
        "app.go:217",
    ),
    Sample(
        "Gin access log",
        '[GIN] 2026/07/30 - 23:07:31 | 500 | 209µs | 127.0.0.1 | GET "/api/x"',
        "ERROR",
        "gin",
    ),
    Sample(
        "Kubernetes (CRI node file)",
        "2026-08-05T10:00:09.987654321Z stderr F connection refused",
        "ERROR",
        None,
    ),
    Sample(
        "GKE (Cloud Logging)",
        '{"severity":"ERROR","timestamp":"2026-08-05T10:00:09Z","resource":'
        '{"labels":{"container_name":"api"}},"jsonPayload":{"message":"boom"}}',
        "ERROR",
        "api",
    ),
    Sample(
        "AKS (Log Analytics)",
        '{"TimeGenerated":"2026-08-05T10:00:09Z","ContainerName":"api",'
        '"LogLevel":"error","LogMessage":"boom"}',
        "ERROR",
        "api",
    ),
    Sample(
        "EKS (CloudWatch export)",
        '{"timestamp":1785924009987,"message":"boom","logStreamName":"api-7f6d"}',
        None,
        "api-7f6d",
    ),
    Sample(
        "Kubernetes audit event",
        '{"apiVersion":"audit.k8s.io/v1","verb":"list","requestURI":"/api/v1/pods",'
        '"responseStatus":{"code":403},"user":{"username":"system:node:x"},'
        '"requestReceivedTimestamp":"2026-08-05T10:00:09Z"}',
        "WARN",
        None,
    ),
    Sample(
        "macOS install.log",
        "2026-06-03 10:52:41-07 localhost Installer Progress[57]: Progress UI Starting",
        "UNKNOWN",
        "Installer Progress",
    ),
]


def run() -> list[tuple[str, bool, str]]:
    """Returns (corpus, ok, detail) for each sample."""
    results = []
    for sample in SAMPLES:
        entry = parse_line(sample.line, 1)
        if entry is None:
            results.append((sample.corpus, False, "not recognised at all"))
            continue

        problems = []
        if sample.expect_level and entry.level != sample.expect_level:
            problems.append(f"level {entry.level} != {sample.expect_level}")
        if sample.expect_service and entry.service != sample.expect_service:
            problems.append(f"service {entry.service!r} != {sample.expect_service!r}")
        if entry.timestamp is None:
            problems.append("no timestamp")
        results.append((sample.corpus, not problems, "; ".join(problems)))
    return results
